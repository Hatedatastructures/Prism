/**
 * @file ProfileRoutes.hpp
 * @brief Profile 编译路由索引与 SNI 选择
 * @details 负责精确路由、最长单标签 wildcard 和默认候选的编译及查询。
 */

#pragma once

#include <Prism/Runtime/Recognition/ProfileTypes.hpp>
#include <Prism/Runtime/Recognition/Candidate.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Prism::Recognition
{

    struct ProfileWildcardRoute
    {
        std::string Suffix;
        CandidateId Candidate{InvalidCandidate};
    };

    struct ProfileRouteIndex
    {
        std::unordered_map<std::string, CandidateId> Exact;
        std::vector<ProfileWildcardRoute> Wildcards;
        CandidateId DefaultCandidate{InvalidCandidate};
    };

    struct ProfileRouteBuildContext
    {
        RecognitionMode Mode{RecognitionMode::Configured};
        const std::vector<RouteBinding>& Routes;
        const std::vector<CandidateSpec>& Candidates;
        const RecognitionBudget& Budget;
        CandidateId DefaultCandidate{InvalidCandidate};
        ProfileRouteIndex& Index;
    };

} // namespace Prism::Recognition

namespace Prism::Recognition::ProfileSupport
{
    [[nodiscard]] auto NormalizeRouteName(std::string_view Value) -> std::string;
    [[nodiscard]] auto IsValidHostLabel(std::string_view Label) noexcept -> bool;
    [[nodiscard]] auto IsValidHostname(std::string_view Host) noexcept -> bool;
    [[nodiscard]] auto IsValidRoutePattern(std::string_view Pattern) noexcept -> bool;
    [[nodiscard]] auto BuildRoutes(ProfileRouteBuildContext Context) -> std::optional<ProfileError>;
    [[nodiscard]] auto LookupRoute(const ProfileRouteIndex& Index, std::string_view Sni)
        -> std::optional<CandidateId>;

} // namespace Prism::Recognition::ProfileSupport
