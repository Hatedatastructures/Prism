/**
 * @file MixedTrialMode.hpp
 * @brief MixedTrial recognition coordinator.
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <system_error>
#include <utility>

#include <Preview/Runtime/Recognition/MixedTrialAttempt.hpp>
#include <Preview/Runtime/Recognition/MixedTrialCleanup.hpp>
#include <Preview/Runtime/Recognition/MixedTrialDecision.hpp>
#include <Preview/Runtime/Recognition/MixedTrialModel.hpp>
#include <Preview/Runtime/Recognition/MixedTrialPlan.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /**
     * @class MixedTrialMode
     * @brief 串行协调结构检查、认证试探、候选决策和提交清理。
     */
    class MixedTrialMode
    {
    private:
        enum class ProbeProgress
        {
            Ready,
            NeedMore,
            Complete,
        };

        struct TrialInput final
        {
            SharedProfile Profile;
            RecognizeResult Result;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            Preview::Diagnose::ContextState Trace;
        };

        struct TrialState final
        {
            RecognizeResult Result;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
            std::vector<CandidateId> Active;
            std::vector<CandidateId> Structural;
            ProbeSnapshot Snapshot{};
            std::size_t Required{0};
            std::size_t CandidateRequired{0};
            bool Indexed{false};
            MixedTrialPlan Plan;
            MixedTrialDecision Decision;
            MixedTrialCleanup Cleanup;

            explicit TrialState(TrialInput Input)
                : Result(std::move(Input.Result)),
                  Inbound(std::move(Input.Inbound)),
                  Buffer(Input.Buffer),
                  Control(std::move(Input.Control)),
                  Plan(Input.Profile),
                  Decision(Input.Profile),
                  Cleanup(std::move(Input.Profile), std::move(Input.Trace))
            {
                Deadline = Cleanup.EffectiveDeadline(Control);
                Active = Plan.AllCandidates();
                Required = Plan.MinimumBoundary(Active);
            }
        };

    public:
        explicit MixedTrialMode(SharedProfile Profile,
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
                 Profile_->Mode() != RecognitionMode::Deterministic))
            {
                co_return Result;
            }

            co_await Net::dispatch(Inbound->Executor(), Net::use_awaitable);

            co_return co_await RunTrial(TrialState{
                TrialInput{Profile_, std::move(Result), std::move(Inbound), &Buffer,
                    std::move(Control), Trace_}});
        }

    private:
        /** @brief 按当前控制状态完成一次受控增量预读。 */
        auto EnsureProbe(TrialState &State) -> Net::awaitable<bool>
        {
            if (State.Cleanup.SetControlTerminal(MixedTrialTerminalRequest{
                    &State.Result, &State.Control, State.Deadline, State.Buffer, &State.Inbound}))
            {
                co_return false;
            }

            const auto FillRace = co_await detail::AwaitWithControl(
                State.Buffer->Ensure(*State.Inbound, State.Required),
                ControlRaceRequest{State.Control, State.Deadline});
            if (FillRace.Controlled)
            {
                detail::SetControlStatus(State.Result, FillRace.Event);
                State.Result = MixedTrialCleanup::CompleteBufferResult(
                    std::move(State.Result), *State.Buffer, State.Inbound);
                co_return false;
            }

            auto Fill = std::move(FillRace.Value);
            State.Result.ProbeBytes = State.Buffer->Size();
            if (State.Cleanup.SetControlTerminal(MixedTrialTerminalRequest{
                    &State.Result, &State.Control, State.Deadline, State.Buffer, &State.Inbound}))
            {
                co_return false;
            }
            detail::NormalizeCandidateStatus(Fill);
            if (Fill.Status != RecognitionStatus::Accepted)
            {
                detail::SetResultStatus(ResultStatusRequest{
                    &State.Result, Fill.Status, Fill.Error, Fill.Status == RecognitionStatus::Polluted});
                State.Result = MixedTrialCleanup::CompleteBufferResult(
                    std::move(State.Result), *State.Buffer, State.Inbound);
                co_return false;
            }
            co_return true;
        }

        /** @brief 完成首字节索引、结构检查和 TLS route 收敛。 */
        auto InspectProbe(TrialState &State) -> ProbeProgress
        {
            if (!State.Indexed)
            {
                State.Active = State.Plan.IndexedCandidates(*State.Buffer);
                State.Indexed = true;
                if (State.Active.empty())
                {
                    detail::SetResultStatus(
                        ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
                    State.Result = MixedTrialCleanup::CompleteBufferResult(
                        std::move(State.Result), *State.Buffer, State.Inbound);
                    return ProbeProgress::Complete;
                }
            }

            State.Snapshot = State.Buffer->Snapshot();
            const auto Current = State.Plan.InspectCandidates(State.Active, State.Snapshot);
            State.Active = Current.Active;
            State.CandidateRequired = Current.Required;
            if (State.Active.empty())
            {
                detail::SetResultStatus(
                    ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
                State.Result = MixedTrialCleanup::CompleteBufferResult(
                    std::move(State.Result), *State.Buffer, State.Inbound);
                return ProbeProgress::Complete;
            }

            if (detail::HasTlsRouteCandidate(*Profile_, State.Active))
            {
                const auto Route = State.Decision.ResolveRoute(State.Snapshot);
                if (Route.NeedMore)
                {
                    if (State.Buffer->Size() >= Profile_->Budget().MaxProbeBytes)
                    {
                        detail::SetResultStatus(
                            ResultStatusRequest{&State.Result, RecognitionStatus::BudgetExceeded, {}});
                        State.Result = MixedTrialCleanup::CompleteBufferResult(
                            std::move(State.Result), *State.Buffer, State.Inbound);
                        return ProbeProgress::Complete;
                    }
                    State.Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                        (std::max)(State.Buffer->Size() + 1, Route.Required));
                    return ProbeProgress::NeedMore;
                }
                if (Route.Applicable)
                {
                    State.Active = State.Decision.RestrictToRoute(std::move(State.Active), Route.Candidate);
                    if (State.Active.empty())
                    {
                        detail::SetResultStatus(
                            ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
                        State.Result = MixedTrialCleanup::CompleteBufferResult(
                            std::move(State.Result), *State.Buffer, State.Inbound);
                        return ProbeProgress::Complete;
                    }
                }
            }

            State.Structural = Current.Structural;
            State.Structural.erase(
                std::remove_if(State.Structural.begin(), State.Structural.end(),
                    [&State](const auto Id)
                    {
                        return std::find(State.Active.begin(), State.Active.end(), Id) == State.Active.end();
                    }),
                State.Structural.end());
            if (!State.Structural.empty())
            {
                return ProbeProgress::Ready;
            }
            if (Current.NeedMore)
            {
                if (State.Buffer->Size() >= Profile_->Budget().MaxProbeBytes)
                {
                    detail::SetResultStatus(
                        ResultStatusRequest{&State.Result, RecognitionStatus::BudgetExceeded, {}});
                    State.Result = MixedTrialCleanup::CompleteBufferResult(
                        std::move(State.Result), *State.Buffer, State.Inbound);
                    return ProbeProgress::Complete;
                }
                const auto TlsRequired = detail::TlsProbeRequired(State.Snapshot);
                State.Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                    (std::max)(State.Buffer->Size() + 1, (std::max)(Current.Required, TlsRequired)));
                return ProbeProgress::NeedMore;
            }
            detail::SetResultStatus(ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
            State.Result = MixedTrialCleanup::CompleteBufferResult(
                std::move(State.Result), *State.Buffer, State.Inbound);
            return ProbeProgress::Complete;
        }

        /** @brief 运行候选认证试探并收口受控终态。 */
        auto PrepareTrial(TrialState &State)
            -> Net::awaitable<std::optional<MixedTrialAttemptResult>>
        {
            MixedTrialAttempt Attempt(MixedTrialAttemptContext{
                Profile_, &State.Result, &State.Control, State.Deadline});
            auto TrialRace = co_await Attempt.Prepare(std::move(State.Structural), State.Snapshot);
            if (TrialRace.Controlled)
            {
                detail::SetControlStatus(State.Result, TrialRace.Event);
                State.Result = MixedTrialCleanup::CompleteBufferResult(
                    std::move(State.Result), *State.Buffer, State.Inbound);
                co_return std::nullopt;
            }
            if (State.Cleanup.SetControlTerminal(MixedTrialTerminalRequest{
                    &State.Result, &State.Control, State.Deadline, State.Buffer, &State.Inbound}))
            {
                co_return std::nullopt;
            }
            co_return std::move(TrialRace.Value);
        }

        auto RunTrial(TrialState State) -> Net::awaitable<RecognizeResult>
        {
            if (!detail::ArmControl(State.Control, State.Inbound, State.Deadline))
            {
                detail::SetResultStatus(ResultStatusRequest{
                    &State.Result, RecognitionStatus::IoError,
                    std::make_error_code(std::errc::operation_not_supported)});
                co_return std::move(State.Result);
            }

            while (true)
            {
                if (!co_await EnsureProbe(State))
                {
                    co_return std::move(State.Result);
                }
                const auto Progress = InspectProbe(State);
                if (Progress == ProbeProgress::Complete)
                {
                    co_return std::move(State.Result);
                }
                if (Progress == ProbeProgress::NeedMore)
                {
                    continue;
                }

                auto Trial = co_await PrepareTrial(State);
                if (!Trial)
                {
                    co_return std::move(State.Result);
                }
                auto TrialResult = std::move(*Trial);
                State.Active = MixedTrialDecision::RemoveRejected(
                    std::move(State.Active), TrialResult.Rejected);
                if (TrialResult.NeedMore)
                {
                    if (State.Buffer->Size() >= Profile_->Budget().MaxProbeBytes)
                    {
                        detail::SetResultStatus(
                            ResultStatusRequest{&State.Result, RecognitionStatus::BudgetExceeded, {}});
                        co_return MixedTrialCleanup::CompleteBufferResult(
                            std::move(State.Result), *State.Buffer, State.Inbound);
                    }
                    State.Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                        (std::max)(State.Buffer->Size() + 1, TrialResult.Required));
                    continue;
                }
                if (TrialResult.Terminal)
                {
                    if (TrialResult.Candidate != InvalidCandidate)
                    {
                        MixedTrialDecision::InitializeResult(
                            State.Result, Profile_->FindCandidate(TrialResult.Candidate));
                    }
                    State.Result.Candidate = TrialResult.Candidate;
                    detail::SetResultStatus(ResultStatusRequest{
                        &State.Result, TrialResult.Status, TrialResult.Error, TrialResult.Polluted});
                    co_return MixedTrialCleanup::CompleteBufferResult(
                        std::move(State.Result), *State.Buffer, State.Inbound);
                }
                if (TrialResult.Prepared.empty())
                {
                    if (!State.Active.empty())
                    {
                        const auto TlsRequired = detail::TlsProbeRequired(State.Snapshot);
                        State.Required = (std::min)(Profile_->Budget().MaxProbeBytes,
                            (std::max)(State.Buffer->Size() + 1,
                                (std::max)(State.CandidateRequired, TlsRequired)));
                        continue;
                    }
                    detail::SetResultStatus(
                        ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
                    co_return MixedTrialCleanup::CompleteBufferResult(
                        std::move(State.Result), *State.Buffer, State.Inbound);
                }

                const auto Winner = MixedTrialDecision::SelectWinner(TrialResult.Prepared);
                if (Winner.Ambiguous)
                {
                    detail::SetResultStatus(
                        ResultStatusRequest{&State.Result, RecognitionStatus::Ambiguous, {}});
                    co_return MixedTrialCleanup::CompleteBufferResult(
                        std::move(State.Result), *State.Buffer, State.Inbound);
                }
                const auto WinnerIt = std::find_if(
                    TrialResult.Prepared.begin(), TrialResult.Prepared.end(),
                    [&Winner](const auto &Candidate) { return Candidate.Id() == Winner.Candidate; });
                auto Prepared = std::move(*WinnerIt);
                const auto Handle = Prepared.Handle();
                MixedTrialDecision::InitializeResult(State.Result, Handle);
                co_return co_await State.Cleanup.CommitPrepared(MixedTrialCommitRequest{
                    std::move(State.Result), std::move(Prepared), Handle, std::move(State.Inbound),
                    State.Buffer, std::move(State.Control), State.Deadline});
            }
        }

    private:
        SharedProfile Profile_;
        Preview::Diagnose::ContextState Trace_;
    };

} // namespace Preview::Recognition
