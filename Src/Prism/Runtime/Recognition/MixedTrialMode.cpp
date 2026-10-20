/** @file MixedTrialMode.cpp @brief 串行混合试探识别协调器实现。 */
#include <Prism/Runtime/Recognition/MixedTrialMode.hpp>
#include <Prism/Runtime/Recognition/MixedTrialDecision.hpp>
#include <Prism/Runtime/Recognition/MixedTrialPlan.hpp>
#include <Prism/Runtime/Recognition/Detail/RecognitionConfig.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Recognition
{
    auto MixedTrialDecision::ResolveRoute(const ProbeSnapshot &Snapshot) const -> detail::RouteDecision
    {
        return detail::ResolveSniRoute(*Profile_, Snapshot);
    }

    auto MixedTrialDecision::RestrictToRoute(std::vector<CandidateId> Candidates,
        const std::optional<CandidateId> &RouteCandidate) const -> std::vector<CandidateId>
    {
        if (!RouteCandidate)
        {
            return Candidates;
        }
        Candidates.erase(std::remove_if(Candidates.begin(), Candidates.end(),
            [&RouteCandidate](const auto Id) { return Id != *RouteCandidate; }), Candidates.end());
        return Candidates;
    }

    auto MixedTrialDecision::RemoveRejected(std::vector<CandidateId> Candidates,
        const std::vector<CandidateId> &Rejected) -> std::vector<CandidateId>
    {
        Candidates.erase(std::remove_if(Candidates.begin(), Candidates.end(),
            [&Rejected](const auto Id)
            {
                return std::find(Rejected.begin(), Rejected.end(), Id) != Rejected.end();
            }), Candidates.end());
        return Candidates;
    }

    auto MixedTrialDecision::SelectWinner(const std::vector<PreparedCandidate> &Prepared)
        -> MixedTrialWinner
    {
        if (Prepared.empty())
        {
            return {};
        }
        const auto Winner = std::max_element(Prepared.begin(), Prepared.end(),
            [](const auto &Left, const auto &Right)
            { return Left.Handle().Priority() < Right.Handle().Priority(); });
        const auto Priority = Winner->Handle().Priority();
        const auto Count = static_cast<std::size_t>(std::count_if(Prepared.begin(), Prepared.end(),
            [Priority](const auto &Candidate) { return Candidate.Handle().Priority() == Priority; }));
        return MixedTrialWinner{Winner->Id(), Count != 1};
    }

    auto MixedTrialDecision::InitializeResult(RecognizeResult &Result, const CandidateHandle &Handle) -> void
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

    auto MixedTrialDecision::NormalizeCommit(RecognizeResult &Result, CommitResult &Committed,
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
        Result.FaultCode = Committed.FaultCode;
        Result.NativeError = Committed.NativeError;
        Result.Carrier = Committed.Metadata;
    }

    auto MixedTrialPlan::AllCandidates() const -> std::vector<CandidateId>
    {
        std::vector<CandidateId> Result;
        if (!Profile_)
        {
            return Result;
        }
        Result.reserve(Profile_->CandidateCount());
        for (std::size_t Index = 0; Index < Profile_->CandidateCount(); ++Index)
        {
            Result.push_back(Profile_->CandidateIdAt(Index));
        }
        return Result;
    }

    auto MixedTrialPlan::MinimumBoundary(const std::vector<CandidateId> &Candidates) const -> std::size_t
    {
        if (!Profile_)
        {
            return 1;
        }
        std::size_t Result = Profile_->Budget().MaxProbeBytes;
        for (const auto Id : Candidates)
        {
            Result = (std::min)(Result, Profile_->FindCandidate(Id).MinimumBytes());
        }
        return (std::max)(std::size_t{1}, Result);
    }

    auto MixedTrialPlan::IndexedCandidates(const ProbeBuffer &Buffer) const -> std::vector<CandidateId>
    {
        if (!Profile_ || Buffer.Data().empty())
        {
            return {};
        }
        const auto FirstByte = std::to_integer<std::uint8_t>(Buffer.Data().front());
        const auto Bitmap = Profile_->LookupCandidates(FirstByte);
        const auto Ordered = AllCandidates();
        std::vector<CandidateId> Result;
        Result.reserve(Bitmap.Count());
        for (const auto Id : Ordered)
        {
            if (Bitmap.Test(Id))
            {
                Result.push_back(Id);
            }
        }
        return Result;
    }

    auto MixedTrialPlan::InspectCandidates(const std::vector<CandidateId> &Candidates,
        const ProbeSnapshot &Snapshot) const -> MixedTrialInspection
    {
        MixedTrialInspection Result;
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
            if (State == MatchState::Structural || State == MatchState::Authenticated)
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
                Result.Required = Result.Required == 0 ? Boundary : (std::min)(Result.Required, Boundary);
            }
        }
        return Result;
    }

    MixedTrialMode::TrialState::TrialState(TrialInput Input)
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

    auto MixedTrialMode::Recognize(
        SharedTransmission Inbound,
        ProbeBuffer& Buffer,
        RecognitionControl Control) -> Net::awaitable<RecognizeResult>
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

    auto MixedTrialMode::EnsureProbe(TrialState& State) -> Net::awaitable<bool>
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
                &State.Result, Fill.Status, Fill.Error,
                Fill.Status == RecognitionStatus::Polluted});
            State.Result = MixedTrialCleanup::CompleteBufferResult(
                std::move(State.Result), *State.Buffer, State.Inbound);
            co_return false;
        }
        co_return true;
    }

    auto MixedTrialMode::InspectProbe(TrialState& State) -> ProbeProgress
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
                State.Active = State.Decision.RestrictToRoute(
                    std::move(State.Active), Route.Candidate);
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
                    return std::find(State.Active.begin(), State.Active.end(), Id) ==
                        State.Active.end();
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
                (std::max)(State.Buffer->Size() + 1,
                    (std::max)(Current.Required, TlsRequired)));
            return ProbeProgress::NeedMore;
        }
        detail::SetResultStatus(
            ResultStatusRequest{&State.Result, RecognitionStatus::NoMatch, {}});
        State.Result = MixedTrialCleanup::CompleteBufferResult(
            std::move(State.Result), *State.Buffer, State.Inbound);
        return ProbeProgress::Complete;
    }

    auto MixedTrialMode::PrepareTrial(TrialState& State)
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

    auto MixedTrialMode::RunTrial(TrialState State) -> Net::awaitable<RecognizeResult>
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
                [&Winner](const auto& Candidate) { return Candidate.Id() == Winner.Candidate; });
            auto Prepared = std::move(*WinnerIt);
            const auto Handle = Prepared.Handle();
            MixedTrialDecision::InitializeResult(State.Result, Handle);
            co_return co_await State.Cleanup.CommitPrepared(MixedTrialCommitRequest{
                std::move(State.Result), std::move(Prepared), Handle, std::move(State.Inbound),
                State.Buffer, std::move(State.Control), State.Deadline});
        }
    }
}
