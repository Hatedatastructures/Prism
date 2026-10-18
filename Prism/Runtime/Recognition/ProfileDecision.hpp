/**
 * @file ProfileDecision.hpp
 * @brief Profile 首字节决策表构建
 * @details 编译期把候选魔数、fallback 和最小预读边界发布到不可变 DecisionTable。
 */

#pragma once

#include <Prism/Runtime/Recognition/DecisionTable.hpp>
#include <Prism/Runtime/Recognition/ProfileTypes.hpp>
#include <Prism/Runtime/Recognition/ProfileValidation.hpp>

#include <optional>
#include <vector>

namespace Prism::Recognition::ProfileSupport
{

    [[nodiscard]] inline auto BuildDecisionTable(const std::vector<CandidateSpec>& Candidates,
        DecisionTable& Decision) -> std::optional<ProfileError>
    {
        for (const auto& Candidate : Candidates)
        {
            if (!Decision.SetMinimumBytes(Candidate.Id, Candidate.MinimumBytes))
            {
                return ProfileError::CandidateIdOutOfRange;
            }
            const auto FirstBytes = FirstBytesFor(Candidate);
            if (Candidate.Fallback || FirstBytes.empty())
            {
                if (!Decision.AddFallback(Candidate.Id))
                {
                    return ProfileError::CandidateIdOutOfRange;
                }
            }
            for (const auto FirstByte : FirstBytes)
            {
                if (!Decision.AddFirstByte(FirstByte, Candidate.Id))
                {
                    return ProfileError::CandidateIdOutOfRange;
                }
            }
        }
        if (!Decision.Seal())
        {
            return ProfileError::InvalidMode;
        }
        return std::nullopt;
    }

} // namespace Prism::Recognition::ProfileSupport
