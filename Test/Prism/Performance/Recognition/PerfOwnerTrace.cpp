/**
 * @file PerfOwnerTrace.cpp
 * @brief owner compare 的固定 trace、生产 SNI profile 与规范化逻辑。
 */

#include "RecognitionPerf.hpp"

#include <Prism/Boundary/Datagram/Classifier.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>

#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;
    using Prism::Recognition::Perf::OwnerCompareVersion;
    using Prism::Recognition::Perf::OwnerInputContract;
    using Prism::Recognition::Perf::FixedUuid;
    using Prism::Recognition::Perf::OwnerRepeatCycles;
    using Prism::Recognition::Perf::OwnerTrace;
    using Prism::Recognition::Perf::OwnerTraceId;
    [[nodiscard]] auto HashBytes(std::uint64_t Hash, std::span<const std::byte> Bytes) noexcept
        -> std::uint64_t
    {
        constexpr std::uint64_t Prime = 1099511628211ULL;
        for (const auto Byte : Bytes)
        {
            Hash ^= std::to_integer<std::uint8_t>(Byte);
            Hash *= Prime;
        }
        return Hash;
    }

    [[nodiscard]] auto HashText(std::uint64_t Hash, const std::string_view Text) noexcept
        -> std::uint64_t
    {
        return HashBytes(Hash, std::as_bytes(std::span(Text.data(), Text.size())));
    }

    [[nodiscard]] auto HashOwnerTraceValue(const OwnerTrace &Trace) noexcept -> std::uint64_t
    {
        std::uint64_t Hash = 14695981039346656037ULL;
        Hash = HashBytes(Hash, std::as_bytes(std::span<const std::uint8_t>(Trace.Uuid)));
        Hash = HashBytes(Hash, Trace.Cid);
        Hash = HashBytes(Hash, Trace.OverlapCid);
        Hash = HashBytes(Hash, Trace.OtherCid);
        Hash = HashBytes(Hash, Trace.AliasCid);
        Hash = HashText(Hash, std::to_string(Trace.Capacity));
        Hash = HashText(Hash, std::to_string(Trace.AliasCount));
        for (const auto &Additional : Trace.AdditionalCids) Hash = HashBytes(Hash, Additional);
        for (const auto &Packet : Trace.CidPackets) Hash = HashBytes(Hash, Packet);
        for (const auto &Name : Trace.Sni) Hash = HashText(Hash, Name);
        for (const auto Candidate : Trace.SniExpected) Hash = HashText(Hash, std::to_string(Candidate));
        for (const auto &[Pattern, Candidate] : Trace.SniRoutes)
        {
            Hash = HashText(Hash, Pattern);
            Hash = HashText(Hash, std::to_string(Candidate));
        }
        for (const auto &Credential : Trace.Credentials) Hash = HashText(Hash, Credential);
        Hash = HashText(Hash, OwnerInputContract);
        Hash = HashText(Hash, OwnerCompareVersion);
        Hash = HashText(Hash, "cid-register-remove-other-alias-sequence");
        Hash = HashText(Hash, std::to_string(OwnerRepeatCycles));
        return Hash;
    }

    [[nodiscard]] auto MakeOwnerLongPacket(const std::span<const std::byte> Cid)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> Packet{std::byte{0xC0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{1}, static_cast<std::byte>(Cid.size())};
        Packet.insert(Packet.end(), Cid.begin(), Cid.end());
        Packet.push_back(std::byte{0});
        Packet.push_back(std::byte{1});
        return Packet;
    }

    [[nodiscard]] auto MakeOwnerShortPacket(const std::span<const std::byte> Cid)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> Packet{std::byte{0x40}};
        Packet.insert(Packet.end(), Cid.begin(), Cid.end());
        Packet.push_back(std::byte{0x01});
        return Packet;
    }

    [[nodiscard]] auto MakeOwnerTrace(const std::size_t Capacity) -> OwnerTrace
    {
        OwnerTrace Trace;
        Trace.Uuid = FixedUuid;
        Trace.Capacity = Capacity;
        Trace.Cid = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
        Trace.OverlapCid = {std::byte{0x11}, std::byte{0x22}};
        Trace.OtherCid = {std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}};
        Trace.AliasCid = {std::byte{0x91}, std::byte{0x92}, std::byte{0x93}, std::byte{0x94}};
        Trace.AdditionalCids.reserve(Capacity);
        for (std::size_t Index = 0; Index < Capacity; ++Index)
        {
            Trace.AdditionalCids.push_back({
                std::byte{0xA0}, static_cast<std::byte>(Index & 0xffU),
                static_cast<std::byte>((Index >> 8U) & 0xffU), std::byte{0xE0}});
        }
        Trace.CidPackets = {
            MakeOwnerLongPacket(Trace.Cid), MakeOwnerLongPacket(Trace.OtherCid),
            {std::byte{0x40}}, MakeOwnerLongPacket(Trace.Cid), MakeOwnerShortPacket(Trace.Cid),
            MakeOwnerLongPacket(Trace.AliasCid)};
        Trace.Sni = {"EDGE.EXAMPLE.COM.", "client.api.example.com", "client.deep.api.example.com",
                     "b.a.deep.api.example.com", "unknown.example.com", ""};
        Trace.SniExpected = {1, 2, 4, 3, 3, 3};
        Trace.SniRoutes = {{"edge.example.com", 1}, {"*.api.example.com", 2},
                           {"*.deep.api.example.com", 4}};
        Trace.SniRoutes.reserve(Capacity);
        for (std::size_t Index = 3; Index < Capacity; ++Index)
        {
            Trace.SniRoutes.emplace_back("*.slot-" + std::to_string(Index) + ".example.com", 3);
        }
        Trace.Credentials = {"owner-password", "wrong-password", "owner-password"};
        Trace.Hash = HashOwnerTraceValue(Trace);
        return Trace;
    }

    [[nodiscard]] auto MakeSniProfile(const OwnerTrace &Trace) -> Core::SharedProfile
    {
        std::vector<Core::CandidateSpec> Candidates;
        for (const auto Id : {Core::CandidateId{1}, Core::CandidateId{2},
                              Core::CandidateId{3}, Core::CandidateId{4}})
        {
            Core::CandidateSpec Candidate;
            Candidate.Id = Id;
            Candidate.Name = "sni-" + std::to_string(Id);
            Candidate.Protocol = Prism::Contract::ProtocolType::Tls;
            Candidate.Kind = Core::CandidateKind::TlsCarrier;
            Candidate.Scheme = "native";
            Candidate.Fallback = true;
            Candidate.MinimumBytes = 1;
            Candidate.Inspect = [](const Core::ProbeSnapshot &) { return Core::MatchState::Structural; };
            Candidate.Commit = [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
            {
                Core::CommitResult Result;
                Result.Candidate = Context.Candidate;
                Result.Status = Core::RecognitionStatus::Accepted;
                Result.Transport = std::move(Context.Inbound);
                co_return Result;
            };
            Candidates.push_back(std::move(Candidate));
        }
        Core::ProfileSpec Spec;
        Spec.Mode = Core::RecognitionMode::MixedTrial;
        Spec.Budget.MaxCandidates = 4;
        Spec.Budget.MaxRoutes = Trace.SniRoutes.size();
        Spec.Candidates = std::move(Candidates);
        Spec.DefaultCandidate = 3;
        for (const auto &[Pattern, Candidate] : Trace.SniRoutes)
        {
            Spec.Routes.push_back(Core::RouteBinding{Pattern, Candidate});
        }
        const auto Built = Core::Profile::Compile(std::move(Spec));
        return Built ? *Built : Core::SharedProfile{};
    }

    [[nodiscard]] auto NormalizeOwnerName(std::string_view Value) -> std::string
    {
        std::string Result;
        Result.reserve(Value.size());
        for (const auto Character : Value)
        {
            const auto Byte = static_cast<unsigned char>(Character);
            Result.push_back(static_cast<char>(Byte >= 'A' && Byte <= 'Z'
                ? Byte + ('a' - 'A') : Byte));
        }
        while (!Result.empty() && Result.back() == '.') Result.pop_back();
        return Result;
    }


}

namespace Prism::Recognition::Perf
{
    auto MakeOwnerTrace(const std::size_t Capacity) -> OwnerTrace { return ::MakeOwnerTrace(Capacity); }
    auto MakeSniProfile(const OwnerTrace &Trace) -> Prism::Recognition::SharedProfile { return ::MakeSniProfile(Trace); }
    auto NormalizeOwnerName(const std::string_view Value) -> std::string { return ::NormalizeOwnerName(Value); }
    auto HashOwnerTrace(const OwnerTrace &Trace) noexcept -> std::uint64_t
    {
        return ::HashOwnerTraceValue(Trace);
    }
    auto ValidateOwnerTraceHash(const OwnerTrace &Trace) noexcept -> bool
    {
        return Trace.Hash != 0U && Trace.Hash == HashOwnerTrace(Trace);
    }
}

