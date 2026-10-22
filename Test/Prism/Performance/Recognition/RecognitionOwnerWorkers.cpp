/**
 * @file RecognitionOwnerWorkers.cpp
 * @brief owner compare 的 CID/SNI/Account worker 与真实对照矩阵 owner。
 */
#include "RecognitionOwnerMeasure.hpp"
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Boundary/Datagram/DatagramClassifier.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

namespace Prism::Recognition::Perf
{
    [[nodiscard]] auto MakeOwnerTrace(const std::size_t Capacity) -> OwnerTrace;
    [[nodiscard]] auto MakeSniProfile(const OwnerTrace &Trace) -> Prism::Recognition::SharedProfile;
    [[nodiscard]] auto NormalizeOwnerName(std::string_view Value) -> std::string;
}
namespace
{
    namespace Core = Prism::Recognition;
    using Prism::Recognition::Perf::MeasureOwner;
    using Prism::Recognition::Perf::MakeOwnerTrace;
    using Prism::Recognition::Perf::MakeSniProfile;
    using Prism::Recognition::Perf::NormalizeOwnerName;
    using Prism::Recognition::Perf::OwnerCaseResult;
    using Prism::Recognition::Perf::OwnerPreflight;
    using Prism::Recognition::Perf::OwnerPreflightReport;
    using Prism::Recognition::Perf::OwnerMeasurementReport;
    using Prism::Recognition::Perf::OwnerMeasurementOptions;
    using Prism::Recognition::Perf::OwnerCompareVersion;
    using Prism::Recognition::Perf::OwnerVariantA;
    using Prism::Recognition::Perf::OwnerVariantB;
    using Prism::Recognition::Perf::OwnerProductionEntryGap;
    using Prism::Recognition::Perf::OwnerCidScales;
    using Prism::Recognition::Perf::OwnerConcurrencies;
    using Prism::Recognition::Perf::OwnerRoundCount;
    using Prism::Recognition::Perf::OwnerRepeatCycles;
    using Prism::Recognition::Perf::OwnerTrace;
    using Prism::Recognition::Perf::OwnerTraceId;
    using Prism::Recognition::Perf::JsonString;
    using Prism::Recognition::Perf::PrintOwnerMeasurement;
    using Prism::Recognition::Perf::PrintOwnerPreflight;
    enum class CidOperation : std::uint8_t
    {
        Register,
        Duplicate,
        RegisteredLong,
        Unknown,
        RegisterOverlap,
        RegisteredShortOverlap,
        RemoveRegistered,
        RemovedLong,
        RemoveOverlap,
        RegisterAlias,
        RegisteredAlias,
        RegisterOther,
        RegisteredOther,
        RemoveOther,
        OtherRemoved,
        Malformed,
        RemoveAlias,
        AliasRemoved,
    };
    [[nodiscard]] auto OwnerCidHash(const std::span<const std::byte> Bytes) noexcept
        -> std::uint64_t
    {
        constexpr std::uint64_t Offset = 14695981039346656037ULL;
        constexpr std::uint64_t Prime = 1099511628211ULL;
        std::uint64_t Hash = Offset;
        const auto Count = (std::min)(Bytes.size(), std::size_t{8});
        for (std::size_t Index = 0; Index < Count; ++Index)
        {
            Hash ^= std::to_integer<std::uint8_t>(Bytes[Index]);
            Hash *= Prime;
        }
        return Hash == 0U ? 1U : Hash;
    }
    struct OwnerQuicExpectation final
    {
        Prism::Boundary::DatagramRoute Route;
        std::uint32_t Version;
        std::span<const std::byte> Cid;
    };
    [[nodiscard]] auto MatchesOwnerQuic(
        const Prism::Boundary::DatagramClassification &Actual,
        const OwnerQuicExpectation &Expected) -> bool
    {
        const auto BytesMatch = Actual.ConnectionIdBytes.size() == Expected.Cid.size() &&
            std::equal(Actual.ConnectionIdBytes.begin(), Actual.ConnectionIdBytes.end(),
                       Expected.Cid.begin());
        return Actual.Kind == Prism::Boundary::DatagramKind::Quic &&
            Actual.Route == Expected.Route &&
            Actual.Error == Prism::Boundary::QuicHeaderError::None &&
            Actual.Version == Expected.Version &&
            Actual.ConnectionId == (Expected.Cid.empty() ? 0U : OwnerCidHash(Expected.Cid)) &&
            BytesMatch;
    }
    [[nodiscard]] auto MatchesOwnerMalformed(
        const Prism::Boundary::DatagramClassification &Actual) -> bool
    {
        return Actual.Kind == Prism::Boundary::DatagramKind::Ordinary &&
            Actual.Route == Prism::Boundary::DatagramRoute::Malformed &&
            Actual.Error == Prism::Boundary::QuicHeaderError::Truncated &&
            Actual.Version == 0U && Actual.ConnectionId == 0U &&
            Actual.ConnectionIdBytes.empty();
    }
    [[nodiscard]] auto MakeOwnerQuic(
        const Prism::Boundary::DatagramRoute Route,
        const std::uint32_t Version,
        const std::span<const std::byte> Cid) -> Prism::Boundary::DatagramClassification
    {
        Prism::Boundary::DatagramClassification Result;
        Result.Kind = Prism::Boundary::DatagramKind::Quic;
        Result.Route = Route;
        Result.Version = Version;
        Result.ConnectionIdBytes.assign(Cid.begin(), Cid.end());
        Result.ConnectionId = Cid.empty() ? 0U : OwnerCidHash(Cid);
        return Result;
    }
    [[nodiscard]] auto MakeOwnerMalformed() -> Prism::Boundary::DatagramClassification
    {
        return {Prism::Boundary::DatagramKind::Ordinary,
                0,
                Prism::Boundary::DatagramRoute::Malformed,
                Prism::Boundary::QuicHeaderError::Truncated,
                0,
                {}};
    }
    struct CidBaselineWorker final
    {
        const OwnerTrace *Trace;
        Prism::Boundary::DatagramClassifier Classifier;
        explicit CidBaselineWorker(const OwnerTrace *TraceValue) : Trace(TraceValue)
        {
            for (const auto &Additional : Trace->AdditionalCids)
            {
                (void)Classifier.RegisterQuicCid(Additional);
            }
        }
        [[nodiscard]] auto operator()(const std::size_t Index) -> bool
        {
            const auto Cid = std::span<const std::byte>(Trace->Cid);
            const auto Overlap = std::span<const std::byte>(Trace->OverlapCid);
            const auto Other = std::span<const std::byte>(Trace->OtherCid);
            switch (static_cast<CidOperation>(Index))
            {
            case CidOperation::Register: return Classifier.RegisterQuicCid(Cid);
            case CidOperation::Duplicate: return !Classifier.RegisterQuicCid(Cid);
            case CidOperation::RegisteredLong:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[0]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::RegisteredCid, 1U, Cid});
            case CidOperation::Unknown:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[1]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::UnknownCid, 1U, Other});
            case CidOperation::RegisterOverlap: return Classifier.RegisterQuicCid(Overlap);
            case CidOperation::RegisteredShortOverlap:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[4]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::RegisteredCid, 0U, Cid});
            case CidOperation::RemoveRegistered:
                Classifier.RemoveQuicCid(Cid);
                return Classifier.QuicCidCount() == Trace->AdditionalCids.size() + 1U;
            case CidOperation::RemovedLong:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[0]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::UnknownCid, 1U, Cid});
            case CidOperation::RemoveOverlap:
                Classifier.RemoveQuicCid(Overlap);
                return Classifier.QuicCidCount() == Trace->AdditionalCids.size();
            case CidOperation::RegisterAlias: return Classifier.RegisterQuicCid(Trace->AliasCid);
            case CidOperation::RegisteredAlias:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[5]),
                    OwnerQuicExpectation{
                        Prism::Boundary::DatagramRoute::RegisteredCid,
                        1U,
                        std::span<const std::byte>(Trace->AliasCid)});
            case CidOperation::RegisterOther: return Classifier.RegisterQuicCid(Other);
            case CidOperation::RegisteredOther:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[1]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::RegisteredCid, 1U, Other});
            case CidOperation::RemoveOther:
                Classifier.RemoveQuicCid(Other);
                return Classifier.QuicCidCount() == Trace->AdditionalCids.size() + 1U;
            case CidOperation::OtherRemoved:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[1]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::UnknownCid, 1U, Other});
            case CidOperation::Malformed:
                return MatchesOwnerMalformed(Classifier.Classify(Trace->CidPackets[2]));
            case CidOperation::RemoveAlias:
                Classifier.RemoveQuicCid(Trace->AliasCid);
                return Classifier.QuicCidCount() == Trace->AdditionalCids.size();
            case CidOperation::AliasRemoved:
                return MatchesOwnerQuic(Classifier.Classify(Trace->CidPackets[5]),
                    OwnerQuicExpectation{
                        Prism::Boundary::DatagramRoute::UnknownCid,
                        1U,
                        std::span<const std::byte>(Trace->AliasCid)});
            }
            return false;
        }
        [[nodiscard]] auto Cleanup() -> bool
        {
            for (const auto &Additional : Trace->AdditionalCids) Classifier.RemoveQuicCid(Additional);
            return Classifier.QuicCidCount() == 0U;
        }
    };
    struct ByteVectorHash final
    {
        [[nodiscard]] auto operator()(const std::vector<std::byte> &Value) const noexcept
            -> std::size_t
        {
            std::uint64_t Hash = 14695981039346656037ULL;
            Hash = OwnerCidHash(std::span<const std::byte>(Value));
            return static_cast<std::size_t>(Hash);
        }
    };
    struct CidCandidateWorker final
    {
        const OwnerTrace *Trace;
        std::unordered_set<std::vector<std::byte>, ByteVectorHash> Registered;
        explicit CidCandidateWorker(const OwnerTrace *TraceValue) : Trace(TraceValue)
        {
            for (const auto &Additional : Trace->AdditionalCids)
            {
                Registered.insert(Additional);
            }
        }
        [[nodiscard]] auto IsRegistered(const std::span<const std::byte> Cid) const -> bool
        {
            return std::any_of(Registered.begin(), Registered.end(),
                               [Cid](const auto &RegisteredCid)
                               {
                                   return RegisteredCid.size() == Cid.size() &&
                                       std::equal(RegisteredCid.begin(), RegisteredCid.end(), Cid.begin());
                               });
        }
        [[nodiscard]] auto Classify(const std::vector<std::byte> &Packet) const
            -> Prism::Boundary::DatagramClassification
        {
            if (Packet.empty())
            {
                return MakeOwnerMalformed();
            }
            const auto First = std::to_integer<std::uint8_t>(Packet.front());
            if ((First & 0x80U) != 0U)
            {
                if (Packet.size() < 6U)
                {
                    return MakeOwnerMalformed();
                }
                const auto Version = (static_cast<std::uint32_t>(
                    std::to_integer<std::uint8_t>(Packet[1])) << 24U) |
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Packet[2])) << 16U) |
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Packet[3])) << 8U) |
                    static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Packet[4]));
                const auto CidLength = std::to_integer<std::uint8_t>(Packet[5]);
                const auto DestinationEnd = 6U + static_cast<std::size_t>(CidLength);
                if (CidLength == 0U || Packet.size() <= DestinationEnd)
                {
                    return MakeOwnerMalformed();
                }
                const auto SourceLength = std::to_integer<std::uint8_t>(Packet[DestinationEnd]);
                const auto HeaderEnd = DestinationEnd + 1U + static_cast<std::size_t>(SourceLength);
                if (Packet.size() < HeaderEnd)
                {
                    return MakeOwnerMalformed();
                }
                const auto Destination = std::span<const std::byte>(Packet).subspan(6U, CidLength);
                const auto Route = IsRegistered(Destination)
                    ? Prism::Boundary::DatagramRoute::RegisteredCid
                    : Prism::Boundary::DatagramRoute::UnknownCid;
                return MakeOwnerQuic(Route, Version, Destination);
            }
            if ((First & 0x40U) == 0U)
            {
                return MakeOwnerQuic(Prism::Boundary::DatagramRoute::Ordinary, 0U,
                                     std::span<const std::byte>{});
            }
            if (Packet.size() < 2U)
            {
                return MakeOwnerMalformed();
            }
            std::span<const std::byte> Matched;
            for (const auto &RegisteredCid : Registered)
            {
                if (RegisteredCid.size() <= Matched.size() || Packet.size() < 1U + RegisteredCid.size())
                {
                    continue;
                }
                const auto Candidate = std::span<const std::byte>(Packet).subspan(1U, RegisteredCid.size());
                if (std::equal(RegisteredCid.begin(), RegisteredCid.end(), Candidate.begin()))
                {
                    Matched = RegisteredCid;
                }
            }
            if (!Matched.empty())
            {
                return MakeOwnerQuic(Prism::Boundary::DatagramRoute::RegisteredCid, 0U, Matched);
            }
            auto Result = MakeOwnerQuic(Prism::Boundary::DatagramRoute::UnknownCid, 0U,
                                        std::span<const std::byte>{});
            Result.ConnectionId = OwnerCidHash(Packet);
            return Result;
        }
        [[nodiscard]] auto operator()(const std::size_t Index) -> bool
        {
            const auto &Cid = Trace->Cid;
            const auto &Other = Trace->OtherCid;
            switch (static_cast<CidOperation>(Index))
            {
            case CidOperation::Register: return Registered.insert(Cid).second;
            case CidOperation::Duplicate: return !Registered.insert(Cid).second;
            case CidOperation::RegisteredLong:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[0]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::RegisteredCid, 1U, Cid});
            case CidOperation::Unknown:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[1]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::UnknownCid, 1U, Other});
            case CidOperation::RegisterOverlap:
                return Registered.insert(Trace->OverlapCid).second;
            case CidOperation::RegisteredShortOverlap:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[4]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::RegisteredCid, 0U, Cid});
            case CidOperation::RemoveRegistered:
                Registered.erase(Cid);
                return Registered.size() == Trace->AdditionalCids.size() + 1U;
            case CidOperation::RemovedLong:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[0]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::UnknownCid, 1U, Cid});
            case CidOperation::RemoveOverlap:
                Registered.erase(Trace->OverlapCid);
                return Registered.size() == Trace->AdditionalCids.size();
            case CidOperation::RegisterAlias:
                return Registered.insert(Trace->AliasCid).second;
            case CidOperation::RegisteredAlias:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[5]),
                    OwnerQuicExpectation{
                        Prism::Boundary::DatagramRoute::RegisteredCid,
                        1U,
                        std::span<const std::byte>(Trace->AliasCid)});
            case CidOperation::RegisterOther: return Registered.insert(Other).second;
            case CidOperation::RegisteredOther:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[1]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::RegisteredCid, 1U, Other});
            case CidOperation::RemoveOther:
                Registered.erase(Other);
                return Registered.size() == Trace->AdditionalCids.size() + 1U;
            case CidOperation::OtherRemoved:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[1]),
                    OwnerQuicExpectation{Prism::Boundary::DatagramRoute::UnknownCid, 1U, Other});
            case CidOperation::Malformed: return MatchesOwnerMalformed(Classify(Trace->CidPackets[2]));
            case CidOperation::RemoveAlias:
                Registered.erase(Trace->AliasCid);
                return Registered.size() == Trace->AdditionalCids.size();
            case CidOperation::AliasRemoved:
                return MatchesOwnerQuic(Classify(Trace->CidPackets[5]),
                    OwnerQuicExpectation{
                        Prism::Boundary::DatagramRoute::UnknownCid,
                        1U,
                        std::span<const std::byte>(Trace->AliasCid)});
            }
            return false;
        }
        [[nodiscard]] auto Cleanup() -> bool { Registered.clear(); return Registered.empty(); }
    };
    struct SniCandidateWorker final
    {
        const OwnerTrace *Trace;
        std::unordered_map<std::string, Core::CandidateId> Exact;
        std::vector<std::pair<std::string, Core::CandidateId>> Wild;
        explicit SniCandidateWorker(const OwnerTrace *TraceValue) : Trace(TraceValue)
        {
            Exact.reserve(Trace->SniRoutes.size());
            Wild.reserve(Trace->SniRoutes.size());
            for (const auto &[Pattern, Candidate] : Trace->SniRoutes)
            {
                if (Pattern.starts_with("*."))
                {
                    Wild.emplace_back(Pattern.substr(1), Candidate);
                }
                else
                {
                    Exact.emplace(Pattern, Candidate);
                }
            }
            std::stable_sort(Wild.begin(), Wild.end(),
                             [](const auto &Left, const auto &Right)
                             { return Left.first.size() > Right.first.size(); });
        }
        [[nodiscard]] auto Lookup(const std::string_view Name) const -> Core::CandidateId
        {
            const auto Normalized = NormalizeOwnerName(Name);
            if (const auto It = Exact.find(Normalized); It != Exact.end())
            {
                return It->second;
            }
            for (const auto &[Suffix, Candidate] : Wild)
            {
                if (Normalized.ends_with(Suffix) && Normalized.size() > Suffix.size() &&
                    std::string_view(Normalized).substr(0, Normalized.size() - Suffix.size()).find('.') ==
                        std::string_view::npos)
                {
                    return Candidate;
                }
            }
            return 3;
        }
        [[nodiscard]] auto operator()(const std::size_t Index) -> bool
        {
            const auto Name = std::string_view(Trace->Sni[Index]);
            return Lookup(Name) == Trace->SniExpected[Index];
        }
        [[nodiscard]] auto Cleanup() -> bool
        {
            Exact.clear(); Wild.clear(); return Exact.empty() && Wild.empty();
        }
    };
    struct SniBaselineWorker final
    {
        Core::SharedProfile Profile;
        const OwnerTrace *Trace;
        [[nodiscard]] auto operator()(const std::size_t Index) -> bool
        {
            const auto Name = std::string_view(Trace->Sni[Index]);
            const auto Candidate = Profile->LookupRoute(Name);
            return Candidate && *Candidate == Trace->SniExpected[Index];
        }
        [[nodiscard]] auto Cleanup() -> bool { Profile.reset(); return !Profile; }
    };
    enum class AccountOperation : std::uint8_t
    {
        InspectGood,
        InspectBad,
        AuthenticateHold,
        AuthenticateQuota,
        Release,
        AuthenticateAfterRelease,
    };
    struct AccountBaselineWorker final
    {
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        Prism::DirectoryAuthenticator Authenticator;
        Prism::Account::AccountLease Held;
        const OwnerTrace *Trace;
        explicit AccountBaselineWorker(const OwnerTrace *TraceValue)
            : Directory(Prism::Testing::ProviderAccount(
                  Prism::Account::Credential::Password("owner-password"), Prism::AccountId{1},
                  {.MaxConnections = 1})),
              Authenticator(Directory->Credentials), Trace(TraceValue)
        {
            if (!Directory->Store->FindById(Prism::AccountId{1}))
            {
                throw std::runtime_error("production account setup failed");
            }
        }

        /** @brief 冷检查只借用凭据；失败/不匹配都按原语义返回 false。 */
        [[nodiscard]] auto Matches(const Prism::Account::CredentialView Credential) const -> bool
        { const auto Result = Authenticator.InspectCredential(Credential); return Result && *Result; }
        [[nodiscard]] auto operator()(const std::size_t Index) -> bool
        {
            const auto Operation = static_cast<AccountOperation>(Index);
            const auto Good = Prism::Account::CredentialView::Password(Trace->Credentials[0]);
            const auto Bad = Prism::Account::CredentialView::Password(Trace->Credentials[1]);
            switch (Operation)
            {
            case AccountOperation::InspectGood: return Matches(Good);
            case AccountOperation::InspectBad: return !Matches(Bad);
            case AccountOperation::AuthenticateHold: {
                auto Result = Authenticator.Authenticate({{}, "owner", Good, {.Now = 1}});
                if (!Result || !static_cast<bool>(*Result)) return false;
                Held = std::move(*Result);
                return true;
            }
            case AccountOperation::AuthenticateQuota: {
                const auto Result = Authenticator.Authenticate({{}, "owner", Good, {.Now = 1}});
                if (Result) return false;
                return Result.error().Native == Prism::Account::MakeFailure(
                    Prism::Account::FailureReason::ConnectionQuota).Native;
            }
            case AccountOperation::Release:
                Held.Release();
                return !Held;
            case AccountOperation::AuthenticateAfterRelease: {
                auto Result = Authenticator.Authenticate({{}, "owner", Good, {.Now = 1}});
                const auto Accepted = static_cast<bool>(Result) && static_cast<bool>(*Result);
                if (Result) Result->Release();
                return Accepted;
            }
            }
            return false;
        }
        [[nodiscard]] auto Cleanup() -> bool { Held.Release(); return !Held; }
    };
    struct AccountCandidateWorker final
    {
        const OwnerTrace *Trace;
        bool Held{false};
        [[nodiscard]] auto operator()(const std::size_t Index) -> bool
        {
            const auto Operation = static_cast<AccountOperation>(Index);
            switch (Operation)
            {
            case AccountOperation::InspectGood: return Trace->Credentials[0] == "owner-password";
            case AccountOperation::InspectBad: return Trace->Credentials[1] != "owner-password";
            case AccountOperation::AuthenticateHold:
                if (Held) return false;
                Held = true;
                return true;
            case AccountOperation::AuthenticateQuota: return Held;
            case AccountOperation::Release:
                Held = false;
                return true;
            case AccountOperation::AuthenticateAfterRelease:
                if (Held) return false;
                Held = true;
                Held = false;
                return true;
            }
            return false;
        }
        [[nodiscard]] auto Cleanup() -> bool { Held = false; return !Held; }
    };

    template <typename Factory>
    [[nodiscard]] auto ValidateOwnerTrace(
        const std::size_t OperationKinds,
        Factory FactoryValue,
        OwnerPreflight &Result) -> bool
    {
        Result.CorrectnessValid = false;
        Result.CleanupValid = false;
        try
        {
            auto Worker = FactoryValue();
            bool Correct = true;
            for (std::size_t Index = 0; Index < OperationKinds; ++Index)
            {
                if (!Worker(Index))
                {
                    Result.Error = "trace operation failed at index " + std::to_string(Index);
                    Correct = false;
                    break;
                }
            }
            Result.CorrectnessValid = Correct;
            try
            {
                Result.CleanupValid = Worker.Cleanup();
            }
            catch (const std::exception &Failure)
            {
                Result.Error = Failure.what();
            }
            catch (...)
            {
                Result.Error = "unknown trace cleanup failure";
            }
            if (!Result.CleanupValid && Result.Error.empty())
            {
                Result.Error = "trace cleanup failed";
            }
            Result.Errors = Result.CorrectnessValid && Result.CleanupValid ? 0U : 1U;
            return Result.Errors == 0U;
        }
        catch (const std::exception &Failure)
        {
            Result.Error = Failure.what();
        }
        catch (...)
        {
            Result.Error = "unknown trace preflight failure";
        }
        Result.Errors = 1U;
        return false;
    }
    struct OwnerTraceCheck final
    {
        std::string_view Owner;
        std::size_t Operations;
        OwnerPreflight &Result;
    };
    template <typename Factory>
    [[nodiscard]] auto CheckOwnerTrace(const OwnerTraceCheck &Check, Factory FactoryValue) -> bool
    {
        OwnerPreflight Local;
        const auto Valid = ValidateOwnerTrace(Check.Operations, std::move(FactoryValue), Local);
        Check.Result.CorrectnessValid = Check.Result.CorrectnessValid && Local.CorrectnessValid;
        Check.Result.CleanupValid = Check.Result.CleanupValid && Local.CleanupValid;
        Check.Result.Errors += Local.Errors;
        if (!Valid && Check.Result.Error.empty())
        {
            Check.Result.Error = std::string(Check.Owner) + ": " + Local.Error;
        }
        return Valid;
    }
    [[nodiscard]] auto PreflightOwnerVariant(
        const OwnerTrace &Trace,
        const bool Baseline,
        OwnerPreflight &Result) -> bool
    {
        Result = OwnerPreflight{};
        Result.HashValid = ValidateOwnerTraceHash(Trace);
        Result.CorrectnessValid = true;
        Result.CleanupValid = true;
        if (!Result.HashValid)
        {
            Result.Errors = 1U;
            Result.Error = "trace hash mismatch";
        }
        bool Passed = Result.HashValid;
        if (Baseline)
        {
            Passed = CheckOwnerTrace(
                         OwnerTraceCheck{"cid", 18, Result},
                         [&Trace] { return CidBaselineWorker{&Trace}; }) && Passed;
            const auto Profile = MakeSniProfile(Trace);
            if (!Profile)
            {
                Result.CorrectnessValid = false;
                Result.CleanupValid = false;
                ++Result.Errors;
                if (Result.Error.empty())
                {
                    Result.Error = "sni: profile construction failed";
                }
                Passed = false;
            }
            else
            {
                Passed = CheckOwnerTrace(OwnerTraceCheck{"sni", 6, Result}, [Profile, &Trace]
                    { return SniBaselineWorker{Profile, &Trace}; }) && Passed;
            }
            Passed = CheckOwnerTrace(
                         OwnerTraceCheck{"account", 6, Result},
                         [&Trace] { return AccountBaselineWorker{&Trace}; }) && Passed;
        }
        else
        {
            Passed = CheckOwnerTrace(
                         OwnerTraceCheck{"cid", 18, Result},
                         [&Trace] { return CidCandidateWorker{&Trace}; }) && Passed;
            Passed = CheckOwnerTrace(
                         OwnerTraceCheck{"sni", 6, Result},
                         [&Trace] { return SniCandidateWorker{&Trace}; }) && Passed;
            Passed = CheckOwnerTrace(
                         OwnerTraceCheck{"account", 6, Result},
                         [&Trace] { return AccountCandidateWorker{&Trace}; }) && Passed;
        }
        return Passed && Result.CorrectnessValid && Result.CleanupValid;
    }
    struct OwnerMeasurementContext final
    {
        const OwnerTrace &Trace;
        std::size_t Round;
        std::size_t Concurrency;
        bool Baseline;
        std::string_view Order;
        std::vector<OwnerCaseResult> &Correctness;
        bool AllPassed{true};
    };
    struct OwnerMeasurementOperation final
    {
        std::string_view Owner;
        std::size_t Operations;
    };
    template <typename Factory>
    auto RunOwnerMeasurement(
        OwnerMeasurementContext &Context,
        const OwnerMeasurementOperation Operation,
        Factory FactoryValue) -> void
    {
        const auto Measurement = MeasureOwner(
            OwnerMeasurementOptions{Context.Concurrency, Operation.Operations, OwnerRepeatCycles}, std::move(FactoryValue));
        const auto SemanticModel = Context.Baseline
            ? OwnerVariantA
            : OwnerVariantB;
        const auto ExpectedOperations =
            Context.Concurrency * Operation.Operations * OwnerRepeatCycles;
        const auto Passed = PrintOwnerMeasurement(OwnerMeasurementReport{
            Operation.Owner, Context.Baseline ? "A" : "B", Context.Round, Context.Concurrency,
            Context.Order, Context.Trace,
            Operation.Owner == "sni" ? "shared_const_profile_thread_local_candidate"
                                      : "per_owner_instance_serial",
            SemanticModel, ExpectedOperations, Measurement});
        Context.Correctness.push_back(OwnerCaseResult{
            std::string(Operation.Owner), Context.Baseline ? "A" : "B", Passed});
        Context.AllPassed = Context.AllPassed && Passed;
    }
    struct OwnerCompareCaseRequest final
    {
        const OwnerTrace &Trace;
        std::size_t Round;
        std::size_t Concurrency;
        bool Baseline;
        std::vector<OwnerCaseResult> &Correctness;
    };
    auto RunOwnerCompareCase(const OwnerCompareCaseRequest &Request) -> bool
    {
        OwnerMeasurementContext Context{Request.Trace, Request.Round, Request.Concurrency,
                                        Request.Baseline,
                                        Request.Round % 2U == 0U ? std::string_view{"AB"}
                                                                  : std::string_view{"BA"},
                                        Request.Correctness};
        if (Request.Baseline)
        {
            RunOwnerMeasurement(Context, OwnerMeasurementOperation{"cid", 18},
                                [&Request] { return CidBaselineWorker{&Request.Trace}; });
            const auto Profile = MakeSniProfile(Request.Trace);
            RunOwnerMeasurement(Context, OwnerMeasurementOperation{"sni", 6},
                                [Profile, &Request]
            {
                if (!Profile) throw std::runtime_error("production SNI profile setup failed");
                return SniBaselineWorker{Profile, &Request.Trace};
            });
            RunOwnerMeasurement(Context, OwnerMeasurementOperation{"account", 6},
                                [&Request] { return AccountBaselineWorker{&Request.Trace}; });
        }
        else
        {
            RunOwnerMeasurement(Context, OwnerMeasurementOperation{"cid", 18},
                                [&Request] { return CidCandidateWorker{&Request.Trace}; });
            RunOwnerMeasurement(Context, OwnerMeasurementOperation{"sni", 6},
                                [&Request] { return SniCandidateWorker{&Request.Trace}; });
            RunOwnerMeasurement(Context, OwnerMeasurementOperation{"account", 6},
                                [&Request] { return AccountCandidateWorker{&Request.Trace}; });
        }
        return Context.AllPassed;
    }
    auto RunOwnerCompare() -> int
    {
        bool AllPassed = true;
        std::vector<OwnerCaseResult> Correctness;
        std::vector<std::uint64_t> TraceHashes;
        TraceHashes.reserve(OwnerCidScales.size());
        for (const auto Capacity : OwnerCidScales)
        {
            const auto Trace = MakeOwnerTrace(Capacity);
            TraceHashes.push_back(Trace.Hash);
            OwnerPreflight PreflightA;
            OwnerPreflight PreflightB;
            const auto AValid = PreflightOwnerVariant(Trace, true, PreflightA);
            const auto BValid = PreflightOwnerVariant(Trace, false, PreflightB);
            const auto AReported = PrintOwnerPreflight(
                OwnerPreflightReport{"A", OwnerVariantA, Trace, PreflightA});
            const auto BReported = PrintOwnerPreflight(
                OwnerPreflightReport{"B", OwnerVariantB, Trace, PreflightB});
            AllPassed = AValid && BValid && AReported && BReported && AllPassed;
            if (!AllPassed)
            {
                return 1;
            }
            for (std::size_t Round = 0; Round < OwnerRoundCount; ++Round)
            {
                for (const auto Concurrency : OwnerConcurrencies)
                {
                    const auto BaselineFirst = Round % 2U == 0U;
                    AllPassed = RunOwnerCompareCase(OwnerCompareCaseRequest{
                        Trace, Round, Concurrency, BaselineFirst, Correctness}) && AllPassed;
                    AllPassed = RunOwnerCompareCase(OwnerCompareCaseRequest{
                        Trace, Round, Concurrency, !BaselineFirst, Correctness}) && AllPassed;
                }
            }
        }
        const auto CorrectnessErrors = static_cast<std::size_t>(std::count_if(
            Correctness.begin(), Correctness.end(), [](const auto &Case) { return !Case.Correct; }));
        const auto ExpectedCases = OwnerCidScales.size() * OwnerRoundCount *
            OwnerConcurrencies.size() * 2U * 3U;
        const auto CaseCountValid = Correctness.size() == ExpectedCases;
        std::cout << "{\"case\":\"owner_compare_correctness\",\"trace_version\":\""
                  << OwnerCompareVersion << "\",\"trace_id\":" << OwnerTraceId
                  << ",\"trace_hashes\":[";
        for (std::size_t Index = 0; Index < TraceHashes.size(); ++Index)
        {
            if (Index != 0U) std::cout << ',';
            std::cout << TraceHashes[Index];
        }
        std::cout << "],\"capacities\":[8,64,1024],\"concurrencies\":[1,2,4],\"rounds\":"
                  << OwnerRoundCount << ",\"order_contract\":\"even_rounds_AB_odd_rounds_BA\","
                  << "\"variant_a\":\"" << OwnerVariantA << "\",\"variant_b\":\""
                  << OwnerVariantB << "\",\"candidate_not_equivalent\":true,"
                  << "\"production_entry_gap\":\"" << JsonString(OwnerProductionEntryGap)
                  << "\",\"preflight_before_metrics\":true,\"cases\":" << Correctness.size()
                  << ",\"expected_cases\":" << ExpectedCases << ",\"case_count_valid\":"
                  << (CaseCountValid ? "true" : "false") << ",\"errors\":" << CorrectnessErrors
                  << ",\"status\":\""
                  << (AllPassed ? "pass" : "fail") << "\"}\n";
        return AllPassed && CaseCountValid && CorrectnessErrors == 0U ? 0 : 1;
    }


}

namespace Prism::Recognition::Perf
{
    auto RunOwnerCompare() -> int { return ::RunOwnerCompare(); }
}
