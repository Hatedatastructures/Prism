/**
 * @file ConfiguredMode.hpp
 * @brief Configured recognition coordinator and decision state owner.
 */

#pragma once

#include <Preview/Runtime/Recognition/CandidateSelection.hpp>
#include <Preview/Runtime/Recognition/ConfiguredAcceptor.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <optional>
#include <system_error>
#include <utility>

namespace Preview::Recognition
{
    /**
     * @class ConfiguredMode
     * @brief Coordinator for a profile with one configured candidate.
     */
    class ConfiguredMode
    {
    private:
        enum class ProbeProgress
        {
            Ready,
            NeedMore,
            Complete,
        };

        struct TerminalRequest
        {
            RecognizeResult* Result{nullptr};
            const RecognitionControl* Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            ProbeBuffer* Buffer{nullptr};
            const SharedTransmission* Inbound{nullptr};
            bool InvokeCancel{true};
        };

        struct PrepareRequest
        {
            CandidateHandle Handle;
            ProbeSnapshot Snapshot;
            const RecognitionControl* Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            RecognizeResult* Result{nullptr};
        };

        struct CommitRequest
        {
            RecognizeResult Result;
            PreparedCandidate Prepared;
            CandidateHandle Handle;
            SharedTransmission Inbound;
            ProbeBuffer* Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
        };

        struct ConfiguredProbeState
        {
            RecognizeResult Result;
            CandidateHandle Handle;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
            std::size_t Required{0};
        };

        struct PreparedProbeResult final
        {
            std::optional<PreparedCandidate> Candidate;
            bool NeedMore{false};
        };

    public:
        explicit ConfiguredMode(SharedProfile Profile,
            Preview::Diagnose::ContextState Trace = Preview::Diagnose::CaptureCurrentContext())
            : Profile_(std::move(Profile)), Trace_(std::move(Trace))
        {
        }

        /**
         * @brief Recognize using the caller-owned probe buffer.
         * @param Inbound Inbound transport.
         * @param Buffer Connection-level pre-read owner.
         * @param Control Optional total deadline and cancellation state.
         * @return Recognition result.
         */
        [[nodiscard]] auto Recognize(SharedTransmission Inbound, ProbeBuffer& Buffer,
            RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            RecognizeResult Result;
            Result.Mode = RecognitionMode::Configured;
            if (Profile_)
            {
                Result.Mode = Profile_->Mode();
            }
            if (!Profile_ || !Inbound || Profile_->Mode() != RecognitionMode::Configured ||
                Profile_->CandidateCount() != 1)
            {
                co_return Result;
            }

            co_await Net::dispatch(Inbound->Executor(), Net::use_awaitable);

            auto Handle = Profile_->FindCandidate(Profile_->ConfiguredCandidate());
            InitializeResult(Result, Handle);
            const auto Deadline = EffectiveDeadline(Control);
            if (!detail::ArmControl(Control, Inbound, Deadline))
            {
                SetStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                    std::make_error_code(std::errc::operation_not_supported)});
                co_return Result;
            }

            const auto Required = Handle.MinimumBytes();
            co_return co_await RunProbe(ConfiguredProbeState{
                std::move(Result), std::move(Handle), std::move(Inbound), &Buffer,
                std::move(Control), Deadline, Required});
        }

    private:
        /** @brief 执行单候选的增量预读、路由、认证准备和一次性提交。 */
        auto RunProbe(ConfiguredProbeState State) -> Net::awaitable<RecognizeResult>
        {
            while (true)
            {
                if (SetControlTerminal(TerminalRequest{&State.Result, &State.Control,
                                                        State.Deadline, State.Buffer, &State.Inbound}))
                {
                    co_return std::move(State.Result);
                }
                const auto FillRace = co_await detail::AwaitWithControl(
                    State.Buffer->Ensure(*State.Inbound, State.Required),
                    ControlRaceRequest{State.Control, State.Deadline});
                if (FillRace.Controlled)
                {
                    detail::SetControlStatus(State.Result, FillRace.Event);
                    co_return CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                   State.Inbound);
                }
                auto Fill = std::move(FillRace.Value);
                State.Result.ProbeBytes = State.Buffer->Size();
                if (SetControlTerminal(TerminalRequest{&State.Result, &State.Control,
                                                        State.Deadline, State.Buffer, &State.Inbound}))
                {
                    co_return std::move(State.Result);
                }
                detail::NormalizeCandidateStatus(Fill);
                if (Fill.Status != RecognitionStatus::Accepted)
                {
                    SetStatus(ResultStatusRequest{&State.Result, Fill.Status, Fill.Error,
                        Fill.Status == RecognitionStatus::Polluted});
                    co_return CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                   State.Inbound);
                }

                const auto Snapshot = State.Buffer->Snapshot();
                const auto Progress = InspectProbe(State, Snapshot);
                if (Progress == ProbeProgress::Complete)
                {
                    co_return std::move(State.Result);
                }
                if (Progress == ProbeProgress::NeedMore)
                {
                    continue;
                }
                auto Prepared = co_await PrepareCandidate(State, Snapshot);
                if (!Prepared.Candidate)
                {
                    if (Prepared.NeedMore)
                    {
                        continue;
                    }
                    co_return std::move(State.Result);
                }
                co_return co_await CommitPrepared(CommitRequest{
                    std::move(State.Result), std::move(*Prepared.Candidate), State.Handle,
                    std::move(State.Inbound), State.Buffer, std::move(State.Control), State.Deadline});
            }
        }

        auto InspectProbe(ConfiguredProbeState &State, const ProbeSnapshot &Snapshot) -> ProbeProgress
        {
            const auto Match = State.Handle.Inspect(Snapshot);
            if (Match == MatchState::NeedMore)
            {
                if (State.Buffer->Size() >= Profile_->Budget().MaxProbeBytes)
                {
                    SetStatus(ResultStatusRequest{&State.Result, RecognitionStatus::BudgetExceeded, {}});
                    State.Result = CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                        State.Inbound);
                    return ProbeProgress::Complete;
                }
                State.Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                    (std::max)(State.Buffer->Size() + 1, detail::TlsProbeRequired(Snapshot)));
                return ProbeProgress::NeedMore;
            }
            if (Match == MatchState::Rejected)
            {
                SetStatus(ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
                State.Result = CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                    State.Inbound);
                return ProbeProgress::Complete;
            }
            if (!detail::IsTlsRouteCandidate(State.Handle))
            {
                return ProbeProgress::Ready;
            }

            const auto Route = detail::ResolveSniRoute(*Profile_, Snapshot);
            if (Route.NeedMore)
            {
                if (State.Buffer->Size() >= Profile_->Budget().MaxProbeBytes)
                {
                    SetStatus(ResultStatusRequest{&State.Result, RecognitionStatus::BudgetExceeded, {}});
                    State.Result = CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                        State.Inbound);
                    return ProbeProgress::Complete;
                }
                State.Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                    (std::max)(State.Buffer->Size() + 1, Route.Required));
                return ProbeProgress::NeedMore;
            }
            if (Route.Applicable && (!Route.Candidate || *Route.Candidate != State.Handle.Id()))
            {
                SetStatus(ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
                State.Result = CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                    State.Inbound);
                return ProbeProgress::Complete;
            }
            return ProbeProgress::Ready;
        }

        auto PrepareCandidate(ConfiguredProbeState &State, const ProbeSnapshot &Snapshot)
            -> Net::awaitable<PreparedProbeResult>
        {
            auto PreparedRace = co_await Prepare(PrepareRequest{
                State.Handle, Snapshot, &State.Control, State.Deadline, &State.Result});
            if (PreparedRace.Controlled)
            {
                detail::SetControlStatus(State.Result, PreparedRace.Event);
                State.Result = CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                    State.Inbound);
                co_return PreparedProbeResult{};
            }
            if (SetControlTerminal(TerminalRequest{&State.Result, &State.Control,
                                                    State.Deadline, State.Buffer, &State.Inbound}))
            {
                co_return PreparedProbeResult{};
            }

            auto PreparedResult = std::move(PreparedRace.Value);
            detail::NormalizeCandidateStatus(PreparedResult);
            PreparedResult.Candidate = State.Handle.Id();
            if (PreparedResult.NeedMore && !PreparedResult.Polluted)
            {
                if ((State.Handle.Kind() == CandidateKind::Opaque || State.Handle.RequiresAuthentication()) &&
                    State.Result.CryptoTrials > 0)
                {
                    --State.Result.CryptoTrials;
                }
                if (State.Buffer->Size() >= Profile_->Budget().MaxProbeBytes)
                {
                    SetStatus(ResultStatusRequest{&State.Result, RecognitionStatus::BudgetExceeded, {}});
                    State.Result = CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                        State.Inbound);
                    co_return PreparedProbeResult{};
                }
                State.Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                                            State.Buffer->Size() + 1);
                co_return PreparedProbeResult{std::nullopt, true};
            }
            if (PreparedResult.Status != RecognitionStatus::Accepted || PreparedResult.Polluted)
            {
                const auto Status = PreparedResult.Polluted
                    ? RecognitionStatus::Polluted : PreparedResult.Status;
                SetStatus(ResultStatusRequest{&State.Result, Status, PreparedResult.Error,
                    PreparedResult.Polluted || Status == RecognitionStatus::Polluted});
                State.Result = CompleteBufferResult(std::move(State.Result), *State.Buffer,
                                                    State.Inbound);
                co_return PreparedProbeResult{};
            }
            co_return PreparedProbeResult{
                std::optional<PreparedCandidate>{
                    std::in_place, State.Handle, std::move(PreparedResult)}, false};
        }

    private:
        [[nodiscard]] auto EffectiveDeadline(const RecognitionControl& Control) const
            -> RecognitionControl::Clock::time_point
        {
            const auto Limit = RecognitionControl::Clock::time_point::max();
            if (Profile_->Budget().Timeout.count() <= 0)
            {
                return Control.Deadline;
            }
            const auto BudgetDeadline = RecognitionControl::Clock::now() + Profile_->Budget().Timeout;
            if (Control.Deadline == Limit)
            {
                return BudgetDeadline;
            }
            return (std::min)(Control.Deadline, BudgetDeadline);
        }

        static auto InitializeResult(RecognizeResult& Result, const CandidateHandle& Handle) -> void
        {
            Result.Candidate = Handle.Id();
            Result.CandidateName = Handle.Name();
            Result.detected = Handle.Protocol();
            Result.scheme = Handle.Scheme();
            if (Result.scheme.empty())
            {
                Result.scheme = Result.CandidateName;
            }
        }

        static auto SetStatus(ResultStatusRequest Request) -> void
        {
            detail::SetResultStatus(std::move(Request));
        }

        static auto CompleteBufferResult(RecognizeResult Result, ProbeBuffer& Buffer,
            const SharedTransmission& Inbound) -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport = Buffer.Replay(Inbound);
            return Result;
        }

        static auto CompleteNoTransportResult(RecognizeResult Result, ProbeBuffer& Buffer) -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport.reset();
            return Result;
        }

        static auto SetControlTerminal(TerminalRequest Request) -> bool
        {
            auto& Result = *Request.Result;
            const auto& Control = *Request.Control;
            if (Control.IsCancelled())
            {
                if (Request.InvokeCancel)
                {
                    detail::InvokeCancel(Control);
                }
                detail::SetControlStatus(Result, RecognitionControlEvent::Cancelled);
                Result = CompleteBufferResult(std::move(Result), *Request.Buffer, *Request.Inbound);
                return true;
            }
            if (Request.Deadline != RecognitionControl::Clock::time_point::max() &&
                RecognitionControl::Clock::now() >= Request.Deadline)
            {
                if (Request.InvokeCancel)
                {
                    detail::InvokeCancel(Control);
                }
                detail::SetControlStatus(Result, RecognitionControlEvent::TimedOut);
                Result = CompleteBufferResult(std::move(Result), *Request.Buffer, *Request.Inbound);
                return true;
            }
            return false;
        }

        static auto RemainingBudget(const RecognitionBudget& Budget,
            RecognitionControl::Clock::time_point Deadline) -> RecognitionBudget
        {
            auto Result = Budget;
            if (Deadline != RecognitionControl::Clock::time_point::max())
            {
                const auto Now = RecognitionControl::Clock::now();
                if (Now >= Deadline)
                {
                    Result.Timeout = std::chrono::milliseconds{0};
                }
                else
                {
                    Result.Timeout = std::chrono::duration_cast<std::chrono::milliseconds>(Deadline - Now);
                }
            }
            return Result;
        }

        auto CommitPrepared(CommitRequest Request) -> Net::awaitable<RecognizeResult>
        {
            auto Result = std::move(Request.Result);
            auto Prepared = std::move(Request.Prepared);
            const auto Handle = Request.Handle;
            auto Inbound = std::move(Request.Inbound);
            auto Control = std::move(Request.Control);
            auto* Buffer = Request.Buffer;
            const auto Deadline = Request.Deadline;
            if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound}))
            {
                co_return Result;
            }

            Result.preread.assign(Buffer->Data().begin(), Buffer->Data().end());
            CommitContext Context;
            Context.Candidate = Handle.Id();
            Context.Inbound = Buffer->Replay(Inbound);
            Context.Bytes = Buffer->Bytes();
            Context.Trace = Trace_;
            auto CommittedRace = co_await detail::AwaitWithControl(Prepared.Commit(std::move(Context)),
                ControlRaceRequest{Control, Deadline});
            auto Committed = std::move(CommittedRace.Value);
            if (CommittedRace.Controlled)
            {
                const auto CleanupFailure = detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                detail::SetControlStatus(Result, CommittedRace.Event);
                detail::RethrowCleanupFailure(CleanupFailure);
                co_return CompleteNoTransportResult(std::move(Result), *Buffer);
            }

            if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound, false}))
            {
                const auto CleanupFailure = detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
                detail::RethrowCleanupFailure(CleanupFailure);
                co_return Result;
            }

            detail::NormalizeCandidateStatus(Committed);
            NormalizeCommit(Result, Committed, Handle);
            if (Committed.Status == RecognitionStatus::Accepted && !Committed.Polluted)
            {
                if (!Committed.Transport)
                {
                    const auto CleanupFailure = detail::CleanupTransports({{}, Inbound});
                    SetStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                        std::make_error_code(std::errc::operation_not_supported)});
                    detail::RethrowCleanupFailure(CleanupFailure);
                }
                else
                {
                    Result.transport = std::move(Committed.Transport);
                }
            }
            else
            {
                const auto CleanupFailure = detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
                detail::RethrowCleanupFailure(CleanupFailure);
            }
            co_return Result;
        }

        auto Prepare(PrepareRequest Request) -> Net::awaitable<detail::ControlRaceResult<PrepareResult>>
        {
            detail::ControlRaceResult<PrepareResult> Outcome;
            const auto& Handle = Request.Handle;
            const auto& Snapshot = Request.Snapshot;
            const auto& Control = *Request.Control;
            const auto Deadline = Request.Deadline;
            auto& Result = *Request.Result;
            if (!Handle.HasPrepare())
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::Accepted;
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            if (Control.IsCancelled())
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::IoError;
                Prepared.Error = std::make_error_code(std::errc::operation_canceled);
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            if (Deadline != RecognitionControl::Clock::time_point::max() &&
                RecognitionControl::Clock::now() >= Deadline)
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::TimedOut;
                Prepared.Error = std::make_error_code(std::errc::timed_out);
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            const bool CryptoTrial = Handle.Kind() == CandidateKind::Opaque || Handle.RequiresAuthentication();
            if (CryptoTrial && Result.CryptoTrials >= Profile_->Budget().MaxCryptoTrials)
            {
                PrepareResult Prepared;
                Prepared.Candidate = Handle.Id();
                Prepared.Status = RecognitionStatus::BudgetExceeded;
                Outcome.Value = std::move(Prepared);
                co_return Outcome;
            }
            // 结构解析与 opaque 认证试探分开计数，不能因提供 prepare 就消耗 crypto 预算。
            if (CryptoTrial) ++Result.CryptoTrials;
            PrepareContext Context;
            Context.Candidate = Handle.Id();
            Context.Snapshot = Snapshot;
            Context.Budget = RemainingBudget(Profile_->Budget(), Deadline);
            co_return co_await detail::AwaitWithControl(Handle.Prepare(std::move(Context)),
                ControlRaceRequest{Control, Deadline});
        }

        static auto NormalizeCommit(RecognizeResult& Result, CommitResult& Committed,
            const CandidateHandle& Handle) -> void
        {
            detail::NormalizeCandidateStatus(Committed);
            Committed.Candidate = Handle.Id();
            Result.Candidate = Handle.Id();
            if (Committed.Polluted || Committed.Status == RecognitionStatus::Polluted)
            {
                Committed.Status = RecognitionStatus::Polluted;
                Result.Polluted = true;
            }
            detail::SetResultStatus(
                ResultStatusRequest{&Result, Committed.Status, Committed.Error, Committed.Polluted});
            Result.transport = Committed.Transport;
            Result.FaultCode = Committed.FaultCode;
            Result.NativeError = Committed.NativeError;
            Result.Carrier = Committed.Metadata;
        }

        SharedProfile Profile_;
        Preview::Diagnose::ContextState Trace_;
    };
} // namespace Preview::Recognition
