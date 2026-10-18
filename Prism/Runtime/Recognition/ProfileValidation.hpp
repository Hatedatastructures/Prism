/**
 * @file ProfileValidation.hpp
 * @brief Profile 启动阶段的模式、预算和候选校验
 * @details 校验只读取 ProfileSpec，不创建在线状态。
 */

#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <unordered_set>
#include <vector>

#include <Prism/Runtime/Recognition/DecisionTable.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/ProfileTypes.hpp>

namespace Prism::Recognition::ProfileSupport
{

    [[nodiscard]] inline auto ValidateMode(RecognitionMode Mode) -> std::optional<ProfileError>
    {
        switch (Mode)
        {
        case RecognitionMode::Configured:
        case RecognitionMode::Deterministic:
        case RecognitionMode::MixedTrial:
            return std::nullopt;
        }
        return ProfileError::InvalidMode;
    }

    [[nodiscard]] inline auto ValidateBudget(const RecognitionBudget &Budget)
        -> std::optional<ProfileError>
    {
        if (Budget.MaxProbeBytes > ProbeBuffer::MaxSupportedBytes)
        {
            return ProfileError::MaxProbeBytesExceeded;
        }
        if (Budget.MaxCryptoTrials > 16)
        {
            return ProfileError::MaxCryptoTrialsExceeded;
        }
        if (Budget.MaxCandidates > CandidateBitmap::Capacity)
        {
            return ProfileError::CandidateCapacityExceeded;
        }
        if (Budget.MaxRoutes > 4096)
        {
            return ProfileError::MaxRoutesExceeded;
        }
        if (Budget.MaxCandidateNameBytes > 1024)
        {
            return ProfileError::CandidateNameTooLong;
        }
        if (Budget.MaxSchemeBytes > 256)
        {
            return ProfileError::SchemeNameTooLong;
        }
        if (Budget.Timeout.count() < 0)
        {
            return ProfileError::InvalidTimeout;
        }
        return std::nullopt;
    }

    [[nodiscard]] inline auto ValidateCandidateCount(const ProfileSpec &Spec)
        -> std::optional<ProfileError>
    {
        if (Spec.Mode == RecognitionMode::Configured && Spec.Candidates.size() != 1)
        {
            return ProfileError::ConfiguredCandidateCount;
        }
        if ((Spec.Mode == RecognitionMode::MixedTrial || Spec.Mode == RecognitionMode::Deterministic) &&
            Spec.Candidates.empty())
        {
            return ProfileError::MixedTrialRequiresCandidate;
        }
        if (Spec.Candidates.size() > Spec.Budget.MaxCandidates)
        {
            return ProfileError::CandidateLimitExceeded;
        }
        if (Spec.Candidates.size() > CandidateBitmap::Capacity)
        {
            return ProfileError::CandidateCapacityExceeded;
        }
        return std::nullopt;
    }

    [[nodiscard]] inline auto RequiresPrepare(const CandidateSpec &Candidate) noexcept -> bool
    {
        return Candidate.RequiresAuthentication || Candidate.Kind == CandidateKind::Opaque;
    }

    [[nodiscard]] inline auto IsOpaque(const CandidateSpec &Candidate) noexcept -> bool
    {
        return Candidate.Kind == CandidateKind::Opaque || Candidate.RequiresAuthentication;
    }

    [[nodiscard]] inline auto IsTlsCandidate(const CandidateSpec &Candidate) noexcept -> bool
    {
        return Candidate.Kind == CandidateKind::TlsCarrier || Candidate.Protocol == Prism::Contract::ProtocolType::Tls;
    }

    [[nodiscard]] inline auto ContainsCandidate(const std::vector<CandidateSpec> &Candidates,
                                                 CandidateId Id) noexcept -> bool
    {
        return std::any_of(Candidates.begin(), Candidates.end(),
                           [Id](const auto &Candidate) { return Candidate.Id == Id; });
    }

    [[nodiscard]] inline auto FirstBytesFor(const CandidateSpec &Candidate)
        -> std::vector<std::uint8_t>
    {
        if (!Candidate.FirstBytes.empty())
        {
            return Candidate.FirstBytes;
        }
        // TLS carrier 没有可配置的应用层魔数，但 record content type
        // 是稳定的 0x16；将其作为隐式索引，避免 route-only TLS 候选
        // 在任意明文首字节上进入 fallback 试探。
        if (IsTlsCandidate(Candidate))
        {
            return {0x16};
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateCandidates(const ProfileSpec &Spec)
        -> std::optional<ProfileError>
    {
        std::array<bool, CandidateBitmap::Capacity> SeenIds{};
        std::unordered_set<std::string> SeenNames;
        for (const auto &Candidate : Spec.Candidates)
        {
            const auto Index = static_cast<std::size_t>(Candidate.Id);
            if (Index >= CandidateBitmap::Capacity)
            {
                return ProfileError::CandidateIdOutOfRange;
            }
            if (SeenIds[Index])
            {
                return ProfileError::DuplicateCandidateId;
            }
            SeenIds[Index] = true;
            if (Candidate.Name.size() > Spec.Budget.MaxCandidateNameBytes)
            {
                return ProfileError::CandidateNameTooLong;
            }
            if (!SeenNames.emplace(Candidate.Name).second)
            {
                return ProfileError::DuplicateCandidateName;
            }
            if (Candidate.Name.empty())
            {
                return ProfileError::EmptyCandidateName;
            }
            if (Candidate.Kind == CandidateKind::TlsCarrier && Candidate.Scheme.empty())
            {
                return ProfileError::MissingCarrierScheme;
            }
            if (Candidate.Scheme.size() > Spec.Budget.MaxSchemeBytes)
            {
                return ProfileError::SchemeNameTooLong;
            }
            if (Candidate.MinimumBytes == 0)
            {
                return ProfileError::InvalidMinimumBytes;
            }
            if (Candidate.MinimumBytes > Spec.Budget.MaxProbeBytes)
            {
                return ProfileError::MinimumBytesExceedsBudget;
            }
            if (!Candidate.Inspect)
            {
                return ProfileError::MissingInspect;
            }
            if (!Candidate.Commit)
            {
                return ProfileError::MissingCommit;
            }
            if (RequiresPrepare(Candidate) && !Candidate.Prepare)
            {
                return ProfileError::MissingPrepare;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] inline auto ValidateDeterministicSelectors(const ProfileSpec &Spec)
        -> std::optional<ProfileError>
    {
        std::array<CandidateId, DecisionTable::FirstByteCount> PlainOwners;
        std::array<CandidateId, DecisionTable::FirstByteCount> TlsOwners;
        PlainOwners.fill(InvalidCandidate);
        TlsOwners.fill(InvalidCandidate);
        for (const auto &Candidate : Spec.Candidates)
        {
            const bool IsTls = IsTlsCandidate(Candidate);
            for (const auto FirstByte : FirstBytesFor(Candidate))
            {
                auto *Owner = &PlainOwners[FirstByte];
                if (IsTls)
                {
                    Owner = &TlsOwners[FirstByte];
                }
                if (!IsTls && *Owner != InvalidCandidate && *Owner != Candidate.Id)
                {
                    return ProfileError::DeterministicSelectorConflict;
                }
                if (!IsTls && TlsOwners[FirstByte] != InvalidCandidate &&
                    TlsOwners[FirstByte] != Candidate.Id)
                {
                    return ProfileError::DeterministicSelectorConflict;
                }
                if (IsTls && PlainOwners[FirstByte] != InvalidCandidate &&
                    PlainOwners[FirstByte] != Candidate.Id)
                {
                    return ProfileError::DeterministicSelectorConflict;
                }
                *Owner = Candidate.Id;
            }
        }
        const auto HasRouteFor = [&Spec](CandidateId Id)
        {
            return Spec.DefaultCandidate == Id || std::any_of(
                Spec.Routes.begin(), Spec.Routes.end(),
                [Id](const auto &Route) { return Route.Candidate == Id; });
        };
        const auto SniCanDisambiguate = [&HasRouteFor](const CandidateSpec &Left,
                                                         const CandidateSpec &Right)
        {
            return IsTlsCandidate(Left) && IsTlsCandidate(Right) &&
                HasRouteFor(Left.Id) && HasRouteFor(Right.Id);
        };
        for (std::size_t LeftIndex = 0; LeftIndex < Spec.Candidates.size(); ++LeftIndex)
        {
            for (std::size_t RightIndex = LeftIndex + 1; RightIndex < Spec.Candidates.size(); ++RightIndex)
            {
                const auto &Left = Spec.Candidates[LeftIndex];
                const auto &Right = Spec.Candidates[RightIndex];
                if ((Left.Fallback || Right.Fallback) && !SniCanDisambiguate(Left, Right))
                {
                    return ProfileError::DeterministicSelectorConflict;
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] inline auto ValidateModeSpecificCandidates(const ProfileSpec &Spec)
        -> std::optional<ProfileError>
    {
        for (const auto &Candidate : Spec.Candidates)
        {
            if (Candidate.Kind == CandidateKind::QuicCarrier ||
                Candidate.Protocol == Prism::Contract::ProtocolType::Hysteria2 || Candidate.Protocol == Prism::Contract::ProtocolType::Tuic)
            {
                return ProfileError::QuicCandidateRequiresGateway;
            }
        }
        if (Spec.DefaultCandidate != InvalidCandidate &&
            !ContainsCandidate(Spec.Candidates, Spec.DefaultCandidate))
        {
            return ProfileError::DanglingRoute;
        }
        if (Spec.Mode == RecognitionMode::Configured)
        {
            if (Spec.Candidates.front().Id != Spec.ConfiguredCandidate)
            {
                return ProfileError::ConfiguredCandidateNotFound;
            }
            return std::nullopt;
        }

        if (Spec.Mode == RecognitionMode::Deterministic)
        {
            if (Spec.ConfiguredCandidate != InvalidCandidate)
            {
                return ProfileError::ConfiguredCandidateNotAllowed;
            }
            if (Spec.Candidates.size() > 1)
            {
                for (const auto &Candidate : Spec.Candidates)
                {
                    const bool HasFirstByteSelector = !Candidate.FirstBytes.empty();
                    const bool HasTlsRoute = std::any_of(
                        Spec.Routes.begin(), Spec.Routes.end(),
                        [&Candidate](const auto &Route) { return Route.Candidate == Candidate.Id; });
                    if (!HasFirstByteSelector && !HasTlsRoute)
                    {
                        return ProfileError::DeterministicCandidateNeedsSelector;
                    }
                    if (HasTlsRoute && !IsTlsCandidate(Candidate))
                    {
                        return ProfileError::DeterministicCandidateNeedsSelector;
                    }
                }
            }
            if (const auto Error = ValidateDeterministicSelectors(Spec); Error)
            {
                return Error;
            }
            return std::nullopt;
        }

        bool HasEarlyResponse = false;
        bool HasOpaque = false;
        for (const auto &Candidate : Spec.Candidates)
        {
            HasEarlyResponse = HasEarlyResponse || Candidate.Kind == CandidateKind::EarlyResponse;
            HasOpaque = HasOpaque || IsOpaque(Candidate);
        }
        if (HasEarlyResponse && HasOpaque)
        {
            return ProfileError::EarlyResponseOpaqueConflict;
        }
        return std::nullopt;
    }

} // namespace Prism::Recognition::ProfileSupport
