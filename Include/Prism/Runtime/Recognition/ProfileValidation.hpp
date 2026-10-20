/**
 * @file ProfileValidation.hpp
 * @brief Profile 启动阶段的模式、预算和候选校验
 * @details 校验只读取 ProfileSpec，不创建在线状态。
 */

#pragma once

#include <optional>
#include <vector>

#include <Prism/Runtime/Recognition/Candidate.hpp>
#include <Prism/Runtime/Recognition/ProfileTypes.hpp>

namespace Prism::Recognition::ProfileSupport
{

    [[nodiscard]] auto ValidateMode(RecognitionMode Mode) -> std::optional<ProfileError>;

    [[nodiscard]] auto ValidateBudget(const RecognitionBudget &Budget)
        -> std::optional<ProfileError>;

    [[nodiscard]] auto ValidateCandidateCount(const ProfileSpec &Spec)
        -> std::optional<ProfileError>;

    [[nodiscard]] auto RequiresPrepare(const CandidateSpec &Candidate) noexcept -> bool;

    [[nodiscard]] auto IsOpaque(const CandidateSpec &Candidate) noexcept -> bool;

    [[nodiscard]] auto IsTlsCandidate(const CandidateSpec &Candidate) noexcept -> bool;

    [[nodiscard]] auto ContainsCandidate(const std::vector<CandidateSpec> &Candidates,
                                          CandidateId Id) noexcept -> bool;

    [[nodiscard]] auto FirstBytesFor(const CandidateSpec &Candidate)
        -> std::vector<std::uint8_t>;

    [[nodiscard]] auto ValidateCandidates(const ProfileSpec &Spec)
        -> std::optional<ProfileError>;

    [[nodiscard]] auto ValidateDeterministicSelectors(const ProfileSpec &Spec)
        -> std::optional<ProfileError>;

    [[nodiscard]] auto ValidateModeSpecificCandidates(const ProfileSpec &Spec)
        -> std::optional<ProfileError>;

} // namespace Prism::Recognition::ProfileSupport
