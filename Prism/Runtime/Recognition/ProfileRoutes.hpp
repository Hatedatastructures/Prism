/**
 * @file ProfileRoutes.hpp
 * @brief Profile 编译路由索引与 SNI 选择
 * @details 负责精确路由、最长单标签 wildcard 和默认候选的编译及查询。
 */

#pragma once

#include <Prism/Runtime/Recognition/ProfileTypes.hpp>
#include <Prism/Runtime/Recognition/ProfileValidation.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
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

    [[nodiscard]] inline auto NormalizeRouteName(std::string_view Value) -> std::string
    {
        std::string Result;
        Result.reserve(Value.size());
        for (const auto Character : Value)
        {
            const auto Byte = static_cast<unsigned char>(Character);
            auto NormalizedByte = Byte;
            if (Byte >= 'A' && Byte <= 'Z')
            {
                NormalizedByte = Byte + ('a' - 'A');
            }
            Result.push_back(static_cast<char>(NormalizedByte));
        }
        while (!Result.empty() && Result.back() == '.')
        {
            Result.pop_back();
        }
        return Result;
    }

    [[nodiscard]] inline auto IsValidHostLabel(std::string_view Label) noexcept -> bool
    {
        if (Label.empty() || Label.front() == '-' || Label.back() == '-')
        {
            return false;
        }
        for (const auto Character : Label)
        {
            const auto Byte = static_cast<unsigned char>(Character);
            const bool IsAlpha = (Byte >= 'a' && Byte <= 'z') || (Byte >= 'A' && Byte <= 'Z');
            const bool IsDigit = Byte >= '0' && Byte <= '9';
            if (!IsAlpha && !IsDigit && Byte != '-')
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto IsValidHostname(std::string_view Host) noexcept -> bool
    {
        if (Host.empty())
        {
            return false;
        }
        std::size_t Begin = 0;
        while (Begin < Host.size())
        {
            const auto Separator = Host.find('.', Begin);
            std::size_t End = Host.size();
            if (Separator != std::string_view::npos)
            {
                End = Separator;
            }
            if (!IsValidHostLabel(Host.substr(Begin, End - Begin)))
            {
                return false;
            }
            if (Separator == std::string_view::npos)
            {
                return true;
            }
            Begin = Separator + 1;
        }
        return false;
    }

    [[nodiscard]] inline auto IsValidRoutePattern(std::string_view Pattern) noexcept -> bool
    {
        if (Pattern.starts_with("*."))
        {
            const auto Suffix = Pattern.substr(2);
            return Suffix.find('*') == std::string_view::npos && IsValidHostname(Suffix);
        }
        return Pattern.find('*') == std::string_view::npos && IsValidHostname(Pattern);
    }

    [[nodiscard]] inline auto BuildRoutes(ProfileRouteBuildContext Context) -> std::optional<ProfileError>
    {
        const bool HasTlsCandidate = std::any_of(Context.Candidates.begin(), Context.Candidates.end(),
            [](const auto& Candidate) { return IsTlsCandidate(Candidate); });
        const bool EnforceTlsTargets = Context.Mode == RecognitionMode::Deterministic ||
            (HasTlsCandidate && Context.Mode == RecognitionMode::MixedTrial);
        if (Context.DefaultCandidate != InvalidCandidate &&
            !ContainsCandidate(Context.Candidates, Context.DefaultCandidate))
        {
            return ProfileError::DanglingRoute;
        }
        if (EnforceTlsTargets && Context.DefaultCandidate != InvalidCandidate)
        {
            const auto It = std::find_if(Context.Candidates.begin(), Context.Candidates.end(),
                [&Context](const auto& Candidate) { return Candidate.Id == Context.DefaultCandidate; });
            if (It != Context.Candidates.end() && !IsTlsCandidate(*It))
            {
                if (Context.Mode == RecognitionMode::Deterministic)
                {
                    return ProfileError::DeterministicRouteRequiresTlsCandidate;
                }
                return ProfileError::TlsRouteRequiresTlsCandidate;
            }
        }

        std::unordered_set<std::string> Seen;
        if (Context.Routes.size() > Context.Budget.MaxRoutes)
        {
            return ProfileError::MaxRoutesExceeded;
        }
        for (const auto& Route : Context.Routes)
        {
            const auto RawPattern = std::string_view(Route.Pattern);
            const auto Pattern = NormalizeRouteName(RawPattern);
            const bool IsWildcard = Pattern.starts_with("*.");
            if (RawPattern.find("..") != std::string_view::npos || !IsValidRoutePattern(Pattern))
            {
                return ProfileError::InvalidRoutePattern;
            }
            if (!ContainsCandidate(Context.Candidates, Route.Candidate))
            {
                return ProfileError::DanglingRoute;
            }
            if (EnforceTlsTargets)
            {
                const auto It = std::find_if(Context.Candidates.begin(), Context.Candidates.end(),
                    [&Route](const auto& Candidate) { return Candidate.Id == Route.Candidate; });
                if (It != Context.Candidates.end() && !IsTlsCandidate(*It))
                {
                    if (Context.Mode == RecognitionMode::Deterministic)
                    {
                        return ProfileError::DeterministicRouteRequiresTlsCandidate;
                    }
                    return ProfileError::TlsRouteRequiresTlsCandidate;
                }
            }
            if (!Seen.emplace(Pattern).second)
            {
                return ProfileError::DuplicateRoute;
            }
            if (IsWildcard)
            {
                Context.Index.Wildcards.push_back(ProfileWildcardRoute{Pattern.substr(1), Route.Candidate});
            }
            else
            {
                Context.Index.Exact.emplace(Pattern, Route.Candidate);
            }
        }
        std::stable_sort(Context.Index.Wildcards.begin(), Context.Index.Wildcards.end(),
            [](const auto& Left, const auto& Right) { return Left.Suffix.size() > Right.Suffix.size(); });
        Context.Index.DefaultCandidate = Context.DefaultCandidate;
        return std::nullopt;
    }

    [[nodiscard]] inline auto LookupRoute(const ProfileRouteIndex& Index, std::string_view Sni)
        -> std::optional<CandidateId>
    {
        const auto Normalized = NormalizeRouteName(Sni);
        if (const auto It = Index.Exact.find(Normalized); It != Index.Exact.end())
        {
            return It->second;
        }
        for (const auto& Route : Index.Wildcards)
        {
            if (!Normalized.ends_with(Route.Suffix) || Normalized.size() <= Route.Suffix.size())
            {
                continue;
            }
            const auto Prefix =
                std::string_view(Normalized).substr(0, Normalized.size() - Route.Suffix.size());
            if (!Prefix.empty() && Prefix.find('.') == std::string_view::npos)
            {
                return Route.Candidate;
            }
        }
        if (Index.DefaultCandidate != InvalidCandidate)
        {
            return Index.DefaultCandidate;
        }
        return std::nullopt;
    }

} // namespace Prism::Recognition::ProfileSupport
