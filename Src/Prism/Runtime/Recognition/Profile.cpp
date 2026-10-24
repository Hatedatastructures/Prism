/**
 * @file Profile.cpp
 * @brief Profile 校验、索引构造与只读查询实现。
 */
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/Candidate.hpp>
#include <Prism/Runtime/Recognition/DecisionTable.hpp>
#include <Prism/Runtime/Recognition/ProfileRoutes.hpp>
#include <Prism/Runtime/Recognition/ProfileValidation.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/ProfileTypes.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Prism::Recognition
{
    [[nodiscard]] auto ToStringView(ProfileError Error) noexcept -> std::string_view
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
}

namespace Prism::Recognition::ProfileSupport
{
    [[nodiscard]] auto RequiresPrepare(const CandidateSpec& Candidate) noexcept -> bool
    {
        return Candidate.RequiresAuthentication || Candidate.Kind == CandidateKind::Opaque;
    }

    [[nodiscard]] auto IsOpaque(const CandidateSpec& Candidate) noexcept -> bool
    {
        return Candidate.Kind == CandidateKind::Opaque || Candidate.RequiresAuthentication;
    }

    [[nodiscard]] auto IsTlsCandidate(const CandidateSpec& Candidate) noexcept -> bool
    {
        return Candidate.Kind == CandidateKind::TlsCarrier ||
            Candidate.Protocol == Prism::Contract::ProtocolType::Tls;
    }

    [[nodiscard]] auto ValidateMode(const RecognitionMode Mode) -> std::optional<ProfileError>
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

    [[nodiscard]] auto ValidateBudget(const RecognitionBudget& Budget)
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

    [[nodiscard]] auto ValidateCandidateCount(const ProfileSpec& Spec)
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

    [[nodiscard]] auto ContainsCandidate(const std::vector<CandidateSpec>& Candidates,
        const CandidateId Id) noexcept -> bool
    {
        return std::any_of(Candidates.begin(), Candidates.end(),
            [Id](const auto& Candidate) { return Candidate.Id == Id; });
    }

    [[nodiscard]] auto FirstBytesFor(const CandidateSpec& Candidate)
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

    [[nodiscard]] auto ValidateCandidates(const ProfileSpec& Spec)
        -> std::optional<ProfileError>
    {
        std::array<bool, CandidateBitmap::Capacity> SeenIds{};
        std::unordered_set<std::string> SeenNames;
        for (const auto& Candidate : Spec.Candidates)
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

    [[nodiscard]] auto ValidateDeterministicSelectors(const ProfileSpec& Spec)
        -> std::optional<ProfileError>
    {
        std::array<CandidateId, DecisionTable::FirstByteCount> PlainOwners;
        std::array<CandidateId, DecisionTable::FirstByteCount> TlsOwners;
        PlainOwners.fill(InvalidCandidate);
        TlsOwners.fill(InvalidCandidate);
        for (const auto& Candidate : Spec.Candidates)
        {
            const bool IsTls = IsTlsCandidate(Candidate);
            for (const auto FirstByte : FirstBytesFor(Candidate))
            {
                auto* Owner = &PlainOwners[FirstByte];
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
        const auto HasRouteFor = [&Spec](const CandidateId Id)
        {
            return Spec.DefaultCandidate == Id || std::any_of(
                Spec.Routes.begin(), Spec.Routes.end(),
                [Id](const auto& Route) { return Route.Candidate == Id; });
        };
        const auto SniCanDisambiguate = [&HasRouteFor](const CandidateSpec& Left,
            const CandidateSpec& Right)
        {
            return IsTlsCandidate(Left) && IsTlsCandidate(Right) &&
                HasRouteFor(Left.Id) && HasRouteFor(Right.Id);
        };
        for (std::size_t LeftIndex = 0; LeftIndex < Spec.Candidates.size(); ++LeftIndex)
        {
            for (std::size_t RightIndex = LeftIndex + 1; RightIndex < Spec.Candidates.size(); ++RightIndex)
            {
                const auto& Left = Spec.Candidates[LeftIndex];
                const auto& Right = Spec.Candidates[RightIndex];
                if ((Left.Fallback || Right.Fallback) && !SniCanDisambiguate(Left, Right))
                {
                    return ProfileError::DeterministicSelectorConflict;
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto ValidateModeSpecificCandidates(const ProfileSpec& Spec)
        -> std::optional<ProfileError>
    {
        for (const auto& Candidate : Spec.Candidates)
        {
            if (Candidate.Kind == CandidateKind::QuicCarrier ||
                Candidate.Protocol == Prism::Contract::ProtocolType::Hysteria2 ||
                Candidate.Protocol == Prism::Contract::ProtocolType::Tuic)
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
                for (const auto& Candidate : Spec.Candidates)
                {
                    const bool HasFirstByteSelector = !Candidate.FirstBytes.empty();
                    const bool HasTlsRoute = std::any_of(
                        Spec.Routes.begin(), Spec.Routes.end(),
                        [&Candidate](const auto& Route) { return Route.Candidate == Candidate.Id; });
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
        for (const auto& Candidate : Spec.Candidates)
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

    [[nodiscard]] auto NormalizeRouteName(const std::string_view Value) -> std::string
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

    [[nodiscard]] auto IsValidHostLabel(const std::string_view Label) noexcept -> bool
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

    [[nodiscard]] auto IsValidHostname(const std::string_view Host) noexcept -> bool
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

    [[nodiscard]] auto IsValidRoutePattern(const std::string_view Pattern) noexcept -> bool
    {
        if (Pattern.starts_with("*."))
        {
            const auto Suffix = Pattern.substr(2);
            return Suffix.find('*') == std::string_view::npos && IsValidHostname(Suffix);
        }
        return Pattern.find('*') == std::string_view::npos && IsValidHostname(Pattern);
    }

    [[nodiscard]] auto BuildRoutes(ProfileRouteBuildContext Context) -> std::optional<ProfileError>
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

    [[nodiscard]] auto LookupRoute(const ProfileRouteIndex& Index, const std::string_view Sni)
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

    [[nodiscard]] auto BuildDecisionTable(const std::vector<CandidateSpec>& Candidates,
        DecisionTable& Decision) -> std::optional<ProfileError>
    {
        for (const auto& Candidate : Candidates)
        {
            if (!Decision.SetMinimumBytes(Candidate.Id, Candidate.MinimumBytes))
                return ProfileError::CandidateIdOutOfRange;
            const auto FirstBytes = FirstBytesFor(Candidate);
            if (Candidate.Fallback || FirstBytes.empty())
                if (!Decision.AddFallback(Candidate.Id))
                    return ProfileError::CandidateIdOutOfRange;
            for (const auto FirstByte : FirstBytes)
                if (!Decision.AddFirstByte(FirstByte, Candidate.Id))
                    return ProfileError::CandidateIdOutOfRange;
        }
        if (!Decision.Seal()) return ProfileError::InvalidMode;
        return std::nullopt;
    }
}

namespace Prism::Recognition
{
    auto CandidateStore::Find(const CandidateId Id) const noexcept -> const CandidateSpec*
    {
        for (const auto& Candidate : Candidates_)
        {
            if (Candidate.Id == Id)
            {
                return &Candidate;
            }
        }
        return nullptr;
    }

    auto Profile::HasTlsCandidate() const noexcept -> bool
    {
        if (!Candidates_)
        {
            return false;
        }
        return std::any_of(Candidates_->Values().begin(), Candidates_->Values().end(),
            [](const CandidateSpec& Candidate) { return ProfileSupport::IsTlsCandidate(Candidate); });
    }

    auto Profile::IndexedCandidates(std::uint8_t FirstByte) const noexcept -> CandidateBitmap
    {
        auto Indexed = Decision_.Lookup(FirstByte);
        const auto Fallback = Decision_.Fallback();
        Indexed.Words[0] &= ~Fallback.Words[0];
        Indexed.Words[1] &= ~Fallback.Words[1];
        return Indexed;
    }

    auto Profile::CandidateName(const CandidateId Id) const -> std::string
    {
        const auto* Candidate = Candidates_ ? Candidates_->Find(Id) : nullptr;
        return Candidate ? Candidate->Name : std::string{};
    }

    auto Profile::CandidateProtocol(const CandidateId Id) const noexcept
        -> Prism::Contract::ProtocolType
    {
        const auto* Candidate = Candidates_ ? Candidates_->Find(Id) : nullptr;
        return Candidate ? Candidate->Protocol : Prism::Contract::ProtocolType::Unknown;
    }

    Profile::Profile(ProfileModel Data)
        : Mode_(Data.Mode), ConfiguredCandidate_(Data.ConfiguredCandidate), Budget_(Data.Budget),
          Candidates_(std::move(Data.Candidates)), Decision_(std::move(Data.Decision)),
          Routes_(std::move(Data.Routes))
    {
    }

    auto DecisionTable::AddFirstByte(const std::uint8_t FirstByte, const CandidateId Id) noexcept -> bool
    {
        if (Sealed_)
        {
            return false;
        }
        return FirstByte_[FirstByte].Set(Id);
    }

    auto DecisionTable::AddFallback(const CandidateId Id) noexcept -> bool
    {
        if (Sealed_)
        {
            return false;
        }
        return Fallback_.Set(Id);
    }

    auto DecisionTable::SetFirstByte(
        const std::uint8_t FirstByte, const CandidateBitmap& Candidates) noexcept -> bool
    {
        if (Sealed_)
        {
            return false;
        }
        FirstByte_[FirstByte] = Candidates;
        return true;
    }

    auto DecisionTable::SetFallback(const CandidateBitmap& Candidates) noexcept -> bool
    {
        if (Sealed_)
        {
            return false;
        }
        Fallback_ = Candidates;
        return true;
    }

    auto DecisionTable::SetMinimumBytes(const CandidateId Id, const std::size_t MinimumBytes) noexcept
        -> bool
    {
        if (Sealed_)
        {
            return false;
        }
        const auto Index = static_cast<std::size_t>(Id);
        if (Index >= CandidateBitmap::Capacity || MinimumBytes == 0)
        {
            return false;
        }
        MinimumBytes_[Index] = MinimumBytes;
        return true;
    }

    auto DecisionTable::Seal() noexcept -> bool
    {
        if (Sealed_)
        {
            return false;
        }
        Sealed_ = true;
        return true;
    }

    auto DecisionTable::Lookup(const std::uint8_t FirstByte) const noexcept -> CandidateBitmap
    {
        auto Candidates = FirstByte_[FirstByte];
        Candidates.Union(Fallback_);
        return Candidates;
    }

    auto DecisionTable::Lookup(const std::span<const std::byte> Data) const noexcept -> DecisionResult
    {
        DecisionResult Result;
        if (Data.empty())
        {
            const auto Indexed = IndexedCandidates();
            Result.Candidates = Indexed;
            const bool HasFallback = Fallback_.Any();
            Result.Candidates.Union(Fallback_);
            if (Result.Candidates.Empty())
            {
                Result.State = MatchState::Rejected;
                return Result;
            }
            if (HasFallback)
            {
                Result.RequiredBytes = RequiredBytesFor(Result.Candidates);
            }
            else
            {
                Result.RequiredBytes = MinimumRequiredBytesFor(Indexed);
            }
            Result.State = MatchState::NeedMore;
            return Result;
        }

        const auto FirstByte = std::to_integer<std::uint8_t>(Data.front());
        Result.Candidates = Lookup(FirstByte);
        if (Result.Candidates.Empty())
        {
            Result.State = MatchState::Rejected;
            return Result;
        }

        Result.RequiredBytes = RequiredBytesFor(Result.Candidates);
        if (Data.size() < Result.RequiredBytes)
        {
            Result.State = MatchState::NeedMore;
            return Result;
        }

        Result.State = MatchState::Structural;
        Result.Deterministic = Result.Candidates.Count() == 1;
        return Result;
    }

    auto DecisionTable::IndexedCandidates() const noexcept -> CandidateBitmap
    {
        CandidateBitmap Candidates;
        for (const auto& Bucket : FirstByte_)
        {
            Candidates.Union(Bucket);
        }
        return Candidates;
    }

    auto DecisionTable::MinimumRequiredBytesFor(const CandidateBitmap& Candidates) const noexcept
        -> std::size_t
    {
        std::size_t RequiredBytes = 1;
        bool Found = false;
        for (std::size_t Index = 0; Index < CandidateBitmap::Capacity; ++Index)
        {
            const auto Id = static_cast<CandidateId>(Index);
            if (Candidates.Test(Id))
            {
                const auto MinimumBytes = (std::max)(std::size_t{1}, MinimumBytes_[Index]);
                if (Found)
                {
                    RequiredBytes = (std::min)(RequiredBytes, MinimumBytes);
                }
                else
                {
                    RequiredBytes = MinimumBytes;
                }
                Found = true;
            }
        }
        return RequiredBytes;
    }

    auto DecisionTable::RequiredBytesFor(const CandidateBitmap& Candidates) const noexcept
        -> std::size_t
    {
        std::size_t RequiredBytes = 1;
        for (std::size_t Index = 0; Index < CandidateBitmap::Capacity; ++Index)
        {
            const auto Id = static_cast<CandidateId>(Index);
            if (Candidates.Test(Id))
            {
                RequiredBytes = (std::max)(RequiredBytes, MinimumBytes_[Index]);
            }
        }
        return RequiredBytes;
    }

    [[nodiscard]] auto Profile::Compile(ProfileSpec Spec)
        -> std::expected<SharedProfile, ProfileError>
    {
        if (const auto Error = ProfileSupport::ValidateMode(Spec.Mode); Error)
            return std::unexpected(*Error);
        if (const auto Error = ProfileSupport::ValidateBudget(Spec.Budget); Error)
            return std::unexpected(*Error);
        if (const auto Error = ProfileSupport::ValidateCandidateCount(Spec); Error)
            return std::unexpected(*Error);
        if (const auto Error = ProfileSupport::ValidateCandidates(Spec); Error)
            return std::unexpected(*Error);
        if (const auto Error = ProfileSupport::ValidateModeSpecificCandidates(Spec); Error)
            return std::unexpected(*Error);

        auto Ordered = std::move(Spec.Candidates);
        std::stable_sort(Ordered.begin(), Ordered.end(),
            [](const auto& Left, const auto& Right)
            {
                if (Left.Tier != Right.Tier) return Left.Tier < Right.Tier;
                return Left.Priority < Right.Priority;
            });

        DecisionTable Decision;
        if (const auto Error = ProfileSupport::BuildDecisionTable(Ordered, Decision); Error)
            return std::unexpected(*Error);

        ProfileRouteIndex Routes;
        const auto RouteError = ProfileSupport::BuildRoutes(ProfileRouteBuildContext{
            Spec.Mode, Spec.Routes, Ordered, Spec.Budget, Spec.DefaultCandidate, Routes});
        if (RouteError) return std::unexpected(*RouteError);

        auto CandidateOwner = std::make_shared<const CandidateStore>(std::move(Ordered));
        ProfileModel Data{Spec.Mode, Spec.ConfiguredCandidate, Spec.Budget,
            std::move(CandidateOwner), std::move(Decision), std::move(Routes)};
        auto Published = std::shared_ptr<Profile>(new Profile(std::move(Data)));
        return SharedProfile(std::move(Published));
    }
}
