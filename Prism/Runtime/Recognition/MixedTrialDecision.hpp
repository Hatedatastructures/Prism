/**
 * @file MixedTrialDecision.hpp
 * @brief MixedTrial 路由收敛、候选胜者和结果元数据 owner。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

#include <Prism/Runtime/Recognition/ConfiguredAcceptor.hpp>
#include <Prism/Runtime/Recognition/CandidateSelection.hpp>
#include <Prism/Runtime/Recognition/MixedTrialModel.hpp>

namespace Prism::Recognition
{

    /**
     * @class MixedTrialDecision
     * @brief 只负责候选集合收敛、优先级决策和结果字段归一化。
     */
    class MixedTrialDecision
    {
    public:
        explicit MixedTrialDecision(SharedProfile Profile) : Profile_(std::move(Profile))
        {
        }

        [[nodiscard]] auto ResolveRoute(const ProbeSnapshot &Snapshot) const -> detail::RouteDecision
        {
            return detail::ResolveSniRoute(*Profile_, Snapshot);
        }

        [[nodiscard]] auto RestrictToRoute(std::vector<CandidateId> Candidates,
                                           const std::optional<CandidateId> &RouteCandidate) const
            -> std::vector<CandidateId>
        {
            if (!RouteCandidate)
            {
                return Candidates;
            }
            Candidates.erase(std::remove_if(Candidates.begin(), Candidates.end(),
                                            [&RouteCandidate](const auto Id)
                                            { return Id != *RouteCandidate; }),
                             Candidates.end());
            return Candidates;
        }

        [[nodiscard]] static auto RemoveRejected(std::vector<CandidateId> Candidates,
                                                 const std::vector<CandidateId> &Rejected)
            -> std::vector<CandidateId>
        {
            Candidates.erase(std::remove_if(Candidates.begin(), Candidates.end(),
                                            [&Rejected](const auto Id)
                                            {
                                                return std::find(Rejected.begin(), Rejected.end(), Id) !=
                                                       Rejected.end();
                                            }),
                             Candidates.end());
            return Candidates;
        }

        [[nodiscard]] static auto SelectWinner(const std::vector<PreparedCandidate> &Prepared)
            -> MixedTrialWinner
        {
            if (Prepared.empty())
            {
                return {};
            }
            const auto Winner = std::max_element(
                Prepared.begin(), Prepared.end(),
                [](const auto &Left, const auto &Right)
                { return Left.Handle().Priority() < Right.Handle().Priority(); });
            const auto Priority = Winner->Handle().Priority();
            const auto Count = static_cast<std::size_t>(std::count_if(
                Prepared.begin(), Prepared.end(),
                [Priority](const auto &Candidate) { return Candidate.Handle().Priority() == Priority; }));
            return MixedTrialWinner{Winner->Id(), Count != 1};
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
            Result.FaultCode = Committed.FaultCode;
            Result.NativeError = Committed.NativeError;
            Result.Carrier = Committed.Metadata;
        }

    private:
        SharedProfile Profile_;
    };

} // namespace Prism::Recognition
