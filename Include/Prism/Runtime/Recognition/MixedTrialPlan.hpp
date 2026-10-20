/**
 * @file MixedTrialPlan.hpp
 * @brief MixedTrial 候选计划和结构检查 owner。
 */

#pragma once

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

#include <Prism/Runtime/Recognition/CandidateSelection.hpp>
#include <Prism/Runtime/Recognition/MixedTrialModel.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>

namespace Prism::Recognition
{

    /**
     * @class MixedTrialPlan
     * @brief 按 Profile 发布顺序建立候选集合和下一次读取边界。
     * @details 只执行索引、边界和纯结构检查，不执行认证 I/O。
     */
    class MixedTrialPlan
    {
    public:
        explicit MixedTrialPlan(SharedProfile Profile) : Profile_(std::move(Profile))
        {
        }

        [[nodiscard]] auto AllCandidates() const -> std::vector<CandidateId>;

        [[nodiscard]] auto MinimumBoundary(const std::vector<CandidateId> &Candidates) const -> std::size_t;

        [[nodiscard]] auto IndexedCandidates(const ProbeBuffer &Buffer) const -> std::vector<CandidateId>;

        [[nodiscard]] auto InspectCandidates(const std::vector<CandidateId> &Candidates,
                                             const ProbeSnapshot &Snapshot) const -> MixedTrialInspection;

    private:
        SharedProfile Profile_;
    };

} // namespace Prism::Recognition
