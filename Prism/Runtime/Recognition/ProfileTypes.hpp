/**
 * @file ProfileTypes.hpp
 * @brief Prism 识别 Profile 的编译输入与错误模型
 * @details 只描述值语义配置，不拥有 Profile 的编译算法或在线状态。
 */

#pragma once

#include <Prism/Runtime/Recognition/Candidate.hpp>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Recognition
{

    /** @enum ProfileError @brief Profile 编译失败原因。 */
    enum class ProfileError : std::uint8_t
    {
        InvalidMode,
        ConfiguredCandidateCount,
        ConfiguredCandidateNotFound,
        ConfiguredCandidateNotAllowed,
        MixedTrialRequiresCandidate,
        DuplicateCandidateId,
        DuplicateCandidateName,
        EmptyCandidateName,
        CandidateIdOutOfRange,
        CandidateLimitExceeded,
        CandidateCapacityExceeded,
        MaxRoutesExceeded,
        CandidateNameTooLong,
        SchemeNameTooLong,
        MaxProbeBytesExceeded,
        MaxCryptoTrialsExceeded,
        InvalidMinimumBytes,
        MinimumBytesExceedsBudget,
        InvalidTimeout,
        MissingInspect,
        MissingPrepare,
        MissingCommit,
        EarlyResponseOpaqueConflict,
        DanglingRoute,
        DuplicateRoute,
        InvalidRoutePattern,
        MissingResolver,
        MissingAuthenticator,
        QuicCandidateRequiresGateway,
        MissingCarrierScheme,
        DeterministicCandidateNeedsSelector,
        DeterministicSelectorConflict,
        DeterministicRouteRequiresTlsCandidate,
        TlsRouteRequiresTlsCandidate,

    };

    /**
     * @brief Profile 错误转为诊断字符串
     * @param Error 编译错误
     * @return 稳定的错误名
     */
    [[nodiscard]] inline auto ToStringView(ProfileError Error) noexcept -> std::string_view
    {
        switch (Error)
        {
        case ProfileError::InvalidMode:
            return "invalid_mode";
        case ProfileError::ConfiguredCandidateCount:
            return "configured_candidate_count";
        case ProfileError::ConfiguredCandidateNotFound:
            return "configured_candidate_not_found";
        case ProfileError::ConfiguredCandidateNotAllowed:
            return "configured_candidate_not_allowed";
        case ProfileError::MixedTrialRequiresCandidate:
            return "mixed_trial_requires_candidate";
        case ProfileError::DuplicateCandidateId:
            return "duplicate_candidate_id";
        case ProfileError::DuplicateCandidateName:
            return "duplicate_candidate_name";
        case ProfileError::EmptyCandidateName:
            return "empty_candidate_name";
        case ProfileError::CandidateIdOutOfRange:
            return "candidate_id_out_of_range";
        case ProfileError::CandidateLimitExceeded:
            return "candidate_limit_exceeded";
        case ProfileError::CandidateCapacityExceeded:
            return "candidate_capacity_exceeded";
        case ProfileError::MaxRoutesExceeded:
            return "max_routes_exceeded";
        case ProfileError::CandidateNameTooLong:
            return "candidate_name_too_long";
        case ProfileError::SchemeNameTooLong:
            return "scheme_name_too_long";
        case ProfileError::MaxProbeBytesExceeded:
            return "max_probe_bytes_exceeded";
        case ProfileError::MaxCryptoTrialsExceeded:
            return "max_crypto_trials_exceeded";
        case ProfileError::InvalidMinimumBytes:
            return "invalid_minimum_bytes";
        case ProfileError::MinimumBytesExceedsBudget:
            return "minimum_bytes_exceeds_budget";
        case ProfileError::InvalidTimeout:
            return "invalid_timeout";
        case ProfileError::MissingInspect:
            return "missing_inspect";
        case ProfileError::MissingPrepare:
            return "missing_prepare";
        case ProfileError::MissingCommit:
            return "missing_commit";
        case ProfileError::EarlyResponseOpaqueConflict:
            return "early_response_opaque_conflict";
        case ProfileError::DanglingRoute:
            return "dangling_route";
        case ProfileError::DuplicateRoute:
            return "duplicate_route";
        case ProfileError::InvalidRoutePattern:
            return "invalid_route_pattern";
        case ProfileError::MissingResolver:
            return "missing_resolver";
        case ProfileError::MissingAuthenticator:
            return "missing_authenticator";
        case ProfileError::QuicCandidateRequiresGateway:
            return "quic_candidate_requires_gateway";
        case ProfileError::MissingCarrierScheme:
            return "missing_carrier_scheme";
        case ProfileError::DeterministicCandidateNeedsSelector:
            return "deterministic_candidate_needs_selector";
        case ProfileError::DeterministicSelectorConflict:
            return "deterministic_selector_conflict";
        case ProfileError::DeterministicRouteRequiresTlsCandidate:
            return "deterministic_route_requires_tls_candidate";
        case ProfileError::TlsRouteRequiresTlsCandidate:
            return "tls_route_requires_tls_candidate";
        }
        return "unknown_profile_error";
    }

    /**
     * @struct RouteBinding
     * @brief SNI 模式到候选 ID 的编译期绑定
     * @details Pattern 支持精确域名和单标签 wildcard（例如 *.example.com）。
     */
    struct RouteBinding
    {
        std::string Pattern;
        CandidateId Candidate{InvalidCandidate};

        RouteBinding() = default;

        RouteBinding(std::string PatternValue, CandidateId CandidateValue)
            : Pattern(std::move(PatternValue)), Candidate(CandidateValue)
        {
        }
    };

    /** @struct ProfileSpec @brief Profile 编译输入。 */
    struct ProfileSpec
    {
        RecognitionMode Mode{RecognitionMode::Configured};
        CandidateId ConfiguredCandidate{InvalidCandidate};
        CandidateId DefaultCandidate{InvalidCandidate};
        RecognitionBudget Budget{};
        std::vector<CandidateSpec> Candidates;
        std::vector<RouteBinding> Routes;
    };

} // namespace Prism::Recognition
