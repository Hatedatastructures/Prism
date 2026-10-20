/** @file MixedTrialAttempt.cpp @brief 有序候选准备与控制竞争实现。 */
#include <Prism/Runtime/Recognition/MixedTrialAttempt.hpp>
#include <Prism/Runtime/Recognition/Detail/RecognitionConfig.hpp>

#include <system_error>
#include <utility>

namespace Prism::Recognition
{
    MixedTrialAttempt::MixedTrialAttempt(MixedTrialAttemptContext Context)
        : Profile_(std::move(Context.Profile)),
          Result_(Context.Result),
          Control_(Context.Control),
          Deadline_(Context.Deadline)
    {
    }

    auto MixedTrialAttempt::Prepare(
        std::vector<CandidateId> Candidates,
        ProbeSnapshot Snapshot)
        -> Net::awaitable<detail::ControlRaceResult<MixedTrialAttemptResult>>
    {
        detail::ControlRaceResult<MixedTrialAttemptResult> RaceResult;
        MixedTrialAttemptResult Outcome;
        if (Profile_->Mode() == RecognitionMode::Deterministic && Candidates.size() != 1)
        {
            Outcome.Status = RecognitionStatus::Ambiguous;
            Outcome.Terminal = true;
            RaceResult.Value = std::move(Outcome);
            co_return RaceResult;
        }

        for (const auto Id : Candidates)
        {
            const auto Handle = Profile_->FindCandidate(Id);
            const bool CryptoTrial = Handle.Kind() == CandidateKind::Opaque;
            Outcome.Candidate = Id;
            if (SetControlTerminal(Outcome))
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
                if (CryptoTrial && Result_->CryptoTrials >= Profile_->Budget().MaxCryptoTrials)
                {
                    Outcome.Status = RecognitionStatus::BudgetExceeded;
                    Outcome.Terminal = true;
                    RaceResult.Value = std::move(Outcome);
                    co_return RaceResult;
                }
                // Cleartext prepare 只解析结构，不消耗 opaque 认证试探预算。
                if (CryptoTrial) ++Result_->CryptoTrials;
                PrepareContext Context;
                Context.Candidate = Id;
                Context.Snapshot = Snapshot;
                Context.Budget = RemainingBudget();
                const auto PreparedRace = co_await detail::AwaitWithControl(
                    Handle.Prepare(std::move(Context)), ControlRaceRequest{*Control_, Deadline_});
                if (PreparedRace.Controlled)
                {
                    RaceResult.Event = PreparedRace.Event;
                    RaceResult.Controlled = true;
                    co_return RaceResult;
                }
                if (SetControlTerminal(Outcome))
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
                if (CryptoTrial && Result_->CryptoTrials > 0)
                {
                    --Result_->CryptoTrials;
                }
                Outcome.NeedMore = true;
                Outcome.Required = Snapshot.Size() + 1;
                break;
            }
            if (PreparedResult.Polluted || PreparedResult.Status == RecognitionStatus::Polluted)
            {
                Outcome.Status = detail::IsCancellationError(PreparedResult.Error)
                    ? RecognitionStatus::IoError : RecognitionStatus::Polluted;
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
                Outcome.Rejected.push_back(Id);
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

    auto MixedTrialAttempt::RemainingBudget() const -> RecognitionBudget
    {
        auto Result = Profile_->Budget();
        if (Deadline_ != RecognitionControl::Clock::time_point::max())
        {
            const auto Now = RecognitionControl::Clock::now();
            Result.Timeout = Now >= Deadline_
                ? std::chrono::milliseconds{0}
                : std::chrono::duration_cast<std::chrono::milliseconds>(Deadline_ - Now);
        }
        return Result;
    }

    auto MixedTrialAttempt::SetControlTerminal(MixedTrialAttemptResult& Outcome) const -> bool
    {
        if (Control_->IsCancelled())
        {
            detail::InvokeCancel(*Control_);
            Outcome.Status = RecognitionStatus::IoError;
            Outcome.Error = std::make_error_code(std::errc::operation_canceled);
            Outcome.Terminal = true;
            return true;
        }
        if (Deadline_ != RecognitionControl::Clock::time_point::max() &&
            RecognitionControl::Clock::now() >= Deadline_)
        {
            detail::InvokeCancel(*Control_);
            Outcome.Status = RecognitionStatus::TimedOut;
            Outcome.Error = std::make_error_code(std::errc::timed_out);
            Outcome.Terminal = true;
            return true;
        }
        return false;
    }
}
