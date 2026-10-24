/**
 * @file MixedTrialDecision.hpp
 * @brief MixedTrial 路由收敛、候选胜者和结果元数据 owner。
 */

#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <Prism/Runtime/Recognition/PreparedCandidate.hpp>
#include <Prism/Runtime/Recognition/CandidateSelection.hpp>
#include <Prism/Runtime/Recognition/MixedTrialModel.hpp>
#include <Prism/Runtime/Recognition/RecognitionConfig.hpp>

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

        [[nodiscard]] auto ResolveRoute(const ProbeSnapshot &Snapshot) const -> detail::RouteDecision;

        [[nodiscard]] auto RestrictToRoute(std::vector<CandidateId> Candidates,
                                           const std::optional<CandidateId> &RouteCandidate) const
            -> std::vector<CandidateId>;

        [[nodiscard]] static auto RemoveRejected(std::vector<CandidateId> Candidates,
                                                 const std::vector<CandidateId> &Rejected)
            -> std::vector<CandidateId>;

        [[nodiscard]] static auto SelectWinner(const std::vector<PreparedCandidate> &Prepared)
            -> MixedTrialWinner;

        static auto InitializeResult(RecognizeResult &Result, const CandidateHandle &Handle) -> void;

        static auto NormalizeCommit(RecognizeResult &Result, CommitResult &Committed,
                                    const CandidateHandle &Handle) -> void;

    private:
        SharedProfile Profile_;
    };

} // namespace Prism::Recognition
