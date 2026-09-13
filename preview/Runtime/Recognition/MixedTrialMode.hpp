/**
 * @file MixedTrialMode.hpp
 * @brief MixedTrial recognition coordinator.
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Runtime/Recognition/ConfiguredMode.hpp>

    namespace Preview::Recognition
    {

    namespace Net = boost::asio;

    /**
     * @class MixedTrialMode
     * @brief Serial structural and authentication trial coordinator.
     */
    class MixedTrialMode
    {
    private:
        struct Inspection
        {
            std::vector<CandidateId> Active;
            std::vector<CandidateId> Structural;
            std::size_t Required{0};
            bool NeedMore{false};
        };

        struct Trial
        {
            std::vector<PreparedCandidate> Prepared;
            CandidateId Candidate{InvalidCandidate};
            RecognitionStatus Status{RecognitionStatus::Accepted};
            std::error_code Error{};
            bool Polluted{false};
            bool Terminal{false};
            bool NeedMore{false};
            std::size_t Required{0};
        };

        struct TerminalRequest
        {
            RecognizeResult *Result{nullptr};
            const RecognitionControl *Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            ProbeBuffer *Buffer{nullptr};
            const SharedTransmission *Inbound{nullptr};
            bool InvokeCancel{true};
        };

        struct PrepareRequest
        {
            std::vector<CandidateId> Candidates;
            ProbeSnapshot Snapshot;
            const RecognitionControl *Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            RecognizeResult *Result{nullptr};
        };

        struct CommitRequest
        {
            RecognizeResult Result;
            PreparedCandidate Prepared;
            CandidateHandle Handle;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
        };

    public:
        explicit MixedTrialMode(SharedProfile Profile) : Profile_(std::move(Profile)) {}

        /**
         * @brief Recognize using the caller-owned probe buffer.
         * @param Inbound Inbound transport.
         * @param Buffer Connection-level pre-read owner.
         * @param Control Optional total deadline and cancellation state.
         * @return Recognition result.
         */
        [[nodiscard]] auto Recognize(SharedTransmission Inbound, ProbeBuffer &Buffer,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            RecognizeResult Result;
            Result.Mode = RecognitionMode::MixedTrial;
            if (Profile_)
            {
                Result.Mode = Profile_->Mode();
            }
            if (!Profile_ || !Inbound || Profile_->CandidateCount() == 0 ||
                (Profile_->Mode() != RecognitionMode::MixedTrial &&
                 Profile_->Mode() != RecognitionMode::DeterministicRoute))
            {
                co_return Result;
            }

            co_await Net::dispatch(Inbound->Executor(), Net::use_awaitable);

            const auto Deadline = EffectiveDeadline(Control);
            if (!detail::ArmControl(Control, Inbound, Deadline))
            {
                SetStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                                              std::make_error_code(std::errc::operation_not_supported)});
                co_return Result;
            }
            auto Active = AllCandidates();
            std::size_t Required = MinimumBoundary(Active);
            bool Indexed = false;
            while (true)
            {
                if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, &Buffer, &Inbound}))
                {
                    co_return Result;
                }
                const auto FillRace = co_await detail::AwaitWithControl(
                    Buffer.Ensure(*Inbound, Required), ControlRaceRequest{Control, Deadline});
                if (FillRace.Controlled)
                {
                    detail::SetControlStatus(Result, FillRace.Event);
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }
                auto Fill = std::move(FillRace.Value);
                Result.ProbeBytes = Buffer.Size();
                if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, &Buffer, &Inbound}))
                {
                    co_return Result;
                }
                detail::NormalizeCandidateStatus(Fill);
                if (Fill.Status != RecognitionStatus::Accepted)
                {
                    SetStatus(ResultStatusRequest{&Result, Fill.Status, Fill.Error,
                                                  Fill.Status == RecognitionStatus::Polluted});
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }

                if (!Indexed)
                {
                    Active = IndexedCandidates(Buffer);
                    Indexed = true;
                    if (Active.empty())
                    {
                        SetStatus(ResultStatusRequest{&Result, RecognitionStatus::NoMatch, {}});
                        co_return CompleteBufferResult(Result, Buffer, Inbound);
                    }
                }

                const auto Snapshot = Buffer.Snapshot();
                const auto Current = InspectCandidates(Active, Snapshot);
                Active = Current.Active;
                if (Active.empty())
                {
                    SetStatus(ResultStatusRequest{&Result, RecognitionStatus::NoMatch, {}});
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }
                if (!Current.Structural.empty())
                {
                    // 完整结构已经确定协议边界；不要为了 opaque fallback
                    // 继续读取，否则客户端可能正在等待该候选的早期响应。
                    Active = Current.Structural;
                }
                else if (Current.NeedMore)
                {
                    if (Buffer.Size() >= Profile_->Budget().MaxProbeBytes)
                    {
                        SetStatus(ResultStatusRequest{&Result, RecognitionStatus::BudgetExceeded, {}});
                        co_return CompleteBufferResult(Result, Buffer, Inbound);
                    }
                    const auto TlsRequired = detail::TlsProbeRequired(Snapshot);
                    Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                                          (std::max)(Buffer.Size() + 1,
                                                     (std::max)(Current.Required, TlsRequired)));
                    continue;
                }

                if (detail::HasTlsRouteCandidate(*Profile_, Active))
                {
                    const auto Route = detail::ResolveSniRoute(*Profile_, Snapshot);
                    if (Route.NeedMore)
                    {
                        if (Buffer.Size() >= Profile_->Budget().MaxProbeBytes)
                        {
                            SetStatus(ResultStatusRequest{&Result, RecognitionStatus::BudgetExceeded, {}});
                            co_return CompleteBufferResult(Result, Buffer, Inbound);
                        }
                        Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                                              (std::max)(Buffer.Size() + 1, Route.Required));
                        continue;
                    }
                    if (Route.Applicable)
                    {
                        if (!Route.Candidate)
                        {
                            SetStatus(ResultStatusRequest{&Result, RecognitionStatus::NoMatch, {}});
                            co_return CompleteBufferResult(Result, Buffer, Inbound);
                        }
                        Active.erase(std::remove_if(Active.begin(), Active.end(),
                                                    [&Route](const auto Id)
                                                    { return Id != *Route.Candidate; }),
                                     Active.end());
                        if (Active.empty())
                        {
                            SetStatus(ResultStatusRequest{&Result, RecognitionStatus::NoMatch, {}});
                            co_return CompleteBufferResult(Result, Buffer, Inbound);
                        }
                    }
                }

                auto TrialRace = co_await PrepareCandidates(
                    PrepareRequest{Active, Snapshot, &Control, Deadline, &Result});
                if (TrialRace.Controlled)
                {
                    detail::SetControlStatus(Result, TrialRace.Event);
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }
                if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, &Buffer, &Inbound}))
                {
                    co_return Result;
                }
                auto TrialResult = std::move(TrialRace.Value);
                if (TrialResult.NeedMore)
                {
                    if (Buffer.Size() >= Profile_->Budget().MaxProbeBytes)
                    {
                        SetStatus(ResultStatusRequest{&Result, RecognitionStatus::BudgetExceeded, {}});
                        co_return CompleteBufferResult(Result, Buffer, Inbound);
                    }
                    Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                                          (std::max)(Buffer.Size() + 1, TrialResult.Required));
                    continue;
                }
                if (TrialResult.Terminal)
                {
                    if (TrialResult.Candidate != InvalidCandidate)
                    {
                        InitializeResult(Result, Profile_->FindCandidate(TrialResult.Candidate));
                    }
                    Result.Candidate = TrialResult.Candidate;
                    SetStatus(ResultStatusRequest{&Result, TrialResult.Status, TrialResult.Error,
                                                  TrialResult.Polluted});
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }
                if (TrialResult.Prepared.empty())
                {
                    SetStatus(ResultStatusRequest{&Result, RecognitionStatus::NoMatch, {}});
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }
                if (TrialResult.Prepared.size() != 1)
                {
                    SetStatus(ResultStatusRequest{&Result, RecognitionStatus::Ambiguous, {}});
                    co_return CompleteBufferResult(Result, Buffer, Inbound);
                }

                auto Prepared = std::move(TrialResult.Prepared.front());
                const auto Handle = Prepared.Handle();
                InitializeResult(Result, Handle);
                co_return co_await CommitPrepared(CommitRequest{std::move(Result), std::move(Prepared), Handle,
                                                                std::move(Inbound), &Buffer, std::move(Control),
                                                                Deadline});
            }
        }

        /**
         * @brief Alternate argument order for callers that own the buffer first.
         * @param Buffer Connection-level pre-read owner.
         * @param Inbound Inbound transport.
         * @param Control Optional total deadline and cancellation state.
         * @return Recognition result.
         */
        [[nodiscard]] auto Recognize(ProbeBuffer &Buffer, SharedTransmission Inbound,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            co_return co_await Recognize(std::move(Inbound), Buffer, std::move(Control));
        }

    private:
        [[nodiscard]] auto EffectiveDeadline(const RecognitionControl &Control) const
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

        [[nodiscard]] auto AllCandidates() const -> std::vector<CandidateId>
        {
            std::vector<CandidateId> Result;
            Result.reserve(Profile_->CandidateCount());
            for (std::size_t Index = 0; Index < Profile_->CandidateCount(); ++Index)
            {
                Result.push_back(Profile_->CandidateIdAt(Index));
            }
            return Result;
        }

        [[nodiscard]] auto MinimumBoundary(const std::vector<CandidateId> &Candidates) const -> std::size_t
        {
            std::size_t Result = Profile_->Budget().MaxProbeBytes;
            for (const auto Id : Candidates)
            {
                const auto Candidate = Profile_->FindCandidate(Id);
                Result = (std::min)(Result, Candidate.MinimumBytes());
            }
            return (std::max)(std::size_t{1}, Result);
        }

        [[nodiscard]] auto IndexedCandidates(const ProbeBuffer &Buffer) const -> std::vector<CandidateId>
        {
            const auto Data = Buffer.Data();
            if (Data.empty())
            {
                return {};
            }
            const auto FirstByte = std::to_integer<std::uint8_t>(Data.front());
            const auto Bitmap = Profile_->LookupCandidates(FirstByte);
            const auto Ordered = AllCandidates();
            std::vector<CandidateId> Result;
            Result.reserve(Bitmap.Count());
            for (const auto Id : Ordered)
            {
                if (Bitmap.Contains(Id))
                {
                    Result.push_back(Id);
                }
            }
            return Result;
        }

        [[nodiscard]] auto InspectCandidates(const std::vector<CandidateId> &Candidates,
                                             const ProbeSnapshot &Snapshot) const -> Inspection
        {
            Inspection Result;
            Result.Active.reserve(Candidates.size());
            for (const auto Id : Candidates)
            {
                const auto Handle = Profile_->FindCandidate(Id);
                const auto State = Handle.Inspect(Snapshot);
                if (State == MatchState::Rejected)
                {
                    continue;
                }
                Result.Active.push_back(Id);
                if (State == MatchState::Structural)
                {
                    Result.Structural.push_back(Id);
                }
                if (State == MatchState::NeedMore)
                {
                    Result.NeedMore = true;
                    const auto Minimum = Handle.MinimumBytes();
                    std::size_t Boundary = Snapshot.Size() + 1;
                    if (Snapshot.Size() < Minimum)
                    {
                        Boundary = Minimum;
                    }
                    if (Result.Required == 0)
                    {
                        Result.Required = Boundary;
                    }
                    else
                    {
                        Result.Required = (std::min)(Result.Required, Boundary);
                    }
                }
            }
            return Result;
        }

        auto PrepareCandidates(PrepareRequest Request)
            -> Net::awaitable<detail::ControlRaceResult<Trial>>
        {
            detail::ControlRaceResult<Trial> RaceResult;
            const auto &Candidates = Request.Candidates;
            const auto &Snapshot = Request.Snapshot;
            const auto &Control = *Request.Control;
            const auto Deadline = Request.Deadline;
            auto &Result = *Request.Result;
            Trial Outcome;
            if (Profile_->Mode() == RecognitionMode::DeterministicRoute && Candidates.size() != 1)
            {
                Outcome.Status = RecognitionStatus::Ambiguous;
                Outcome.Terminal = true;
                RaceResult.Value = std::move(Outcome);
                co_return RaceResult;
            }
            for (const auto Id : Candidates)
            {
                const auto Handle = Profile_->FindCandidate(Id);
                Outcome.Candidate = Id;
                if (SetControlTerminalForPrepare(Control, Deadline, Outcome))
                {
                    RaceResult.Value = std::move(Outcome);
                    co_return RaceResult;
                }
                PrepareResult PreparedResult;
                if (!Handle.HasPrepare())
                {
                    PreparedResult.Candidate = Id;
                    PreparedResult.Status = RecognitionStatus::Accepted;
                }
                else
                {
                    if (Result.CryptoTrials >= Profile_->Budget().MaxCryptoTrials)
                    {
                        Outcome.Candidate = Id;
                        Outcome.Status = RecognitionStatus::BudgetExceeded;
                        Outcome.Terminal = true;
                        RaceResult.Value = std::move(Outcome);
                        co_return RaceResult;
                    }
                    ++Result.CryptoTrials;
                    PrepareContext Context;
                    Context.Candidate = Id;
                    Context.Snapshot = Snapshot;
                    Context.Budget = RemainingBudget(Deadline);
                    const auto PreparedRace = co_await detail::AwaitWithControl(
                        Handle.Prepare(std::move(Context)), ControlRaceRequest{Control, Deadline});
                    if (PreparedRace.Controlled)
                    {
                        RaceResult.Event = PreparedRace.Event;
                        RaceResult.Controlled = true;
                        co_return RaceResult;
                    }
                    if (SetControlTerminalForPrepare(Control, Deadline, Outcome))
                    {
                        RaceResult.Value = std::move(Outcome);
                        co_return RaceResult;
                    }
                    PreparedResult = std::move(PreparedRace.Value);
                    detail::NormalizeCandidateStatus(PreparedResult);
                }
                PreparedResult.Candidate = Id;
                if (PreparedResult.NeedMore && !PreparedResult.Polluted)
                {
                    if (Result.CryptoTrials > 0)
                    {
                        --Result.CryptoTrials;
                    }
                    Outcome.NeedMore = true;
                    Outcome.Required = Snapshot.Size() + 1;
                    break;
                }
                if (PreparedResult.Polluted || PreparedResult.Status == RecognitionStatus::Polluted)
                {
                    Outcome.Candidate = Id;
                    if (detail::IsCancellationError(PreparedResult.Error))
                    {
                        Outcome.Status = RecognitionStatus::IoError;
                    }
                    else
                    {
                        Outcome.Status = RecognitionStatus::Polluted;
                    }
                    Outcome.Error = PreparedResult.Error;
                    Outcome.Polluted = true;
                    Outcome.Terminal = true;
                    RaceResult.Value = std::move(Outcome);
                    co_return RaceResult;
                }
                if (PreparedResult.Status == RecognitionStatus::Accepted)
                {
                    Outcome.Prepared.emplace_back(Handle, std::move(PreparedResult));
                    continue;
                }
                if (PreparedResult.Status == RecognitionStatus::NoMatch)
                {
                    continue;
                }
                Outcome.Status = PreparedResult.Status;
                Outcome.Candidate = Id;
                Outcome.Error = PreparedResult.Error;
                Outcome.Terminal = true;
                RaceResult.Value = std::move(Outcome);
                co_return RaceResult;
            }
            RaceResult.Value = std::move(Outcome);
            co_return RaceResult;
        }

        auto CommitPrepared(CommitRequest Request) -> Net::awaitable<RecognizeResult>
        {
            auto Result = std::move(Request.Result);
            auto Prepared = std::move(Request.Prepared);
            const auto Handle = Request.Handle;
            auto Inbound = std::move(Request.Inbound);
            auto Control = std::move(Request.Control);
            auto *Buffer = Request.Buffer;
            const auto Deadline = Request.Deadline;
            if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound}))
            {
                co_return Result;
            }

            Result.preread.assign(Buffer->Data().begin(), Buffer->Data().end());
            CommitContext Context;
            Context.Candidate = Handle.Id();
            Context.Inbound = Buffer->Replay(Inbound);
            auto CommittedRace = co_await detail::AwaitWithControl(
                Prepared.Commit(std::move(Context)), ControlRaceRequest{Control, Deadline});
            auto Committed = std::move(CommittedRace.Value);
            if (CommittedRace.Controlled)
            {
                detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                detail::SetControlStatus(Result, CommittedRace.Event);
                co_return CompleteNoTransportResult(std::move(Result), *Buffer);
            }

            if (SetControlTerminal(TerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound, false}))
            {
                detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
                co_return Result;
            }

            detail::NormalizeCandidateStatus(Committed);
            NormalizeCommit(Result, Committed, Handle);
            if (Committed.Status == RecognitionStatus::Accepted && !Committed.Polluted)
            {
                if (!Committed.Transport)
                {
                    detail::CleanupTransports({{}, Inbound});
                    SetStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                                                  std::make_error_code(std::errc::operation_not_supported)});
                }
                else
                {
                    Result.transport = std::move(Committed.Transport);
                }
            }
            else
            {
                detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
            }
            co_return Result;
        }

        [[nodiscard]] auto RemainingBudget(RecognitionControl::Clock::time_point Deadline) const
            -> RecognitionBudget
        {
            auto Result = Profile_->Budget();
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

        static auto SetControlTerminalForPrepare(const RecognitionControl &Control,
                                                 RecognitionControl::Clock::time_point Deadline,
                                                 Trial &Result) -> bool
        {
            if (Control.IsCancelled())
            {
                detail::InvokeCancel(Control);
                Result.Status = RecognitionStatus::IoError;
                Result.Error = std::make_error_code(std::errc::operation_canceled);
                Result.Polluted = false;
                Result.Terminal = true;
                return true;
            }
            if (Deadline != RecognitionControl::Clock::time_point::max() &&
                RecognitionControl::Clock::now() >= Deadline)
            {
                detail::InvokeCancel(Control);
                Result.Status = RecognitionStatus::TimedOut;
                Result.Error = std::make_error_code(std::errc::timed_out);
                Result.Terminal = true;
                return true;
            }
            return false;
        }

        static auto InitializeResult(RecognizeResult &Result, const CandidateHandle &Handle) -> void
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

        static auto CompleteBufferResult(RecognizeResult Result, ProbeBuffer &Buffer,
                                         const SharedTransmission &Inbound) -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport = Buffer.Replay(Inbound);
            return Result;
        }

        static auto CompleteNoTransportResult(RecognizeResult Result, ProbeBuffer &Buffer)
            -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport.reset();
            return Result;
        }

        static auto SetControlTerminal(TerminalRequest Request) -> bool
        {
            auto &Result = *Request.Result;
            const auto &Control = *Request.Control;
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

        static auto NormalizeCommit(RecognizeResult &Result, CommitResult &Committed,
                                    const CandidateHandle &Handle) -> void
        {
            detail::NormalizeCandidateStatus(Committed);
            Committed.Candidate = Handle.Id();
            Result.Candidate = Handle.Id();
            if (Committed.Polluted || Committed.Status == RecognitionStatus::Polluted)
            {
                Committed.Status = RecognitionStatus::Polluted;
                Result.Polluted = true;
            }
            detail::SetResultStatus(ResultStatusRequest{&Result, Committed.Status, Committed.Error,
                                                        Committed.Polluted});
            Result.transport = Committed.Transport;
        }

        SharedProfile Profile_;
    };

} // namespace Preview::Recognition
