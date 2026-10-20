/**
 * @file ProfileTypes.hpp
 * @brief Prism 识别 Profile 的编译输入与错误模型
 * @details 只描述值语义配置，不拥有 Profile 的编译算法或在线状态。
 */

#pragma once

#include <Prism/Runtime/Recognition/Candidate.hpp>

#include <cstdint>
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
    [[nodiscard]] auto ToStringView(ProfileError Error) noexcept -> std::string_view;

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
