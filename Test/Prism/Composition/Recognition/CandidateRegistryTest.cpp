#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
/**
 * @file CandidateRegistryTest.cpp
 * @brief Settings candidate registry behavior tests.
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/CandidateRegistry.hpp>
#include <Prism/Composition/Recognition/TrusttunnelCandidate.hpp>
#include <Prism/Composition/Recognition/TrusttunnelCandidateFailure.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace
{

    namespace Composition = Prism::Composition::Recognition;
    namespace Core = Prism::Recognition;
    namespace Net = boost::asio;

    auto MakeHttpBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        auto Binding = Composition::CandidateFactory::MakeHttp(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority, Candidate.Tier,
                                          Candidate.Fallback},
            Prism::Testing::MakeHttp1Binding());
        return Binding;
    }

    auto MakeVlessBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        Prism::Vless::ServerConfig Configuration;
        Configuration.EnableUdp = Candidate.UdpEnabled;
        return Prism::Testing::MakeVlessCandidate(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority,
                Candidate.Tier, Candidate.Fallback}, std::move(Configuration));
    }

    auto MakeTrojanBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        Prism::Trojan::ServerConfig Configuration;
        Configuration.Password = "candidate-registry-test-password";
        Configuration.EnableUdp = Candidate.UdpEnabled;
        return Prism::Testing::MakeTrojanCandidate(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority,
                Candidate.Tier, Candidate.Fallback}, std::move(Configuration));
    }

    auto MakeVmessBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        Prism::Vmess::ServerConfig Configuration;
        Configuration.EnableUdp = Candidate.UdpEnabled;
        return Prism::Testing::MakeVmessCandidate(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority,
                Candidate.Tier, Candidate.Fallback}, std::move(Configuration));
    }

    auto MakeCarrierRegistration() -> Composition::CandidateRegistry::CarrierRegistration
    {
        return {{}, [](Prism::Recognition::CarrierAcceptInput Input)
            -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
        {
            Prism::Recognition::CarrierAcceptResult Result;
            Result.Transport = std::move(Input.Inbound);
            co_return Result;
        }, {}};
    }

    auto RegisterDefaultCarrier(Composition::CandidateRegistry &Registry,
        const std::string_view Name) -> bool
    {
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor)
        {
            return false;
        }
        return Registry.RegisterTlsCarrier(Descriptor->Slot(), {}, MakeCarrierRegistration());
    }

    auto AppendU16(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    auto AppendU24(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    auto MakeExtension(std::uint16_t Type, const std::vector<std::uint8_t> &Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        AppendU16(Result, Type);
        AppendU16(Result, Payload.size());
        Result.insert(Result.end(), Payload.begin(), Payload.end());
        return Result;
    }

    auto MakeEchClientHello(std::string_view ServerName)
        -> std::vector<std::byte>
    {
        std::vector<std::uint8_t> Names{0};
        AppendU16(Names, ServerName.size());
        Names.insert(Names.end(), ServerName.begin(), ServerName.end());
        std::vector<std::uint8_t> Sni;
        AppendU16(Sni, Names.size());
        Sni.insert(Sni.end(), Names.begin(), Names.end());

        const std::vector<std::uint8_t> AlpnList{2, 'h', '2'};
        std::vector<std::uint8_t> AlpnPayload;
        AppendU16(AlpnPayload, AlpnList.size());
        AlpnPayload.insert(AlpnPayload.end(), AlpnList.begin(), AlpnList.end());
        const auto AlpnExtension = MakeExtension(0x0010, AlpnPayload);

        const auto SniExtension = MakeExtension(0x0000, Sni);
        const auto VersionsExtension = MakeExtension(0x002B, {0x02, 0x03, 0x04});
        const auto EchExtension = MakeExtension(0xFE0D, {0x01});
        std::vector<std::uint8_t> Extensions;
        for (const auto &Extension : {SniExtension, AlpnExtension, VersionsExtension, EchExtension})
        {
            Extensions.insert(Extensions.end(), Extension.begin(), Extension.end());
        }

        std::vector<std::uint8_t> Body{0x03, 0x03};
        Body.insert(Body.end(), 32, 0x42);
        Body.push_back(0);
        AppendU16(Body, 2);
        Body.push_back(0x13);
        Body.push_back(0x01);
        Body.push_back(1);
        Body.push_back(0);
        AppendU16(Body, Extensions.size());
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());

        std::vector<std::uint8_t> Handshake{0x01};
        AppendU24(Handshake, Body.size());
        Handshake.insert(Handshake.end(), Body.begin(), Body.end());
        std::vector<std::byte> Record{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03},
            static_cast<std::byte>((Handshake.size() >> 8) & 0xFFU),
            static_cast<std::byte>(Handshake.size() & 0xFFU)};
        for (const auto Byte : Handshake)
        {
            Record.push_back(static_cast<std::byte>(Byte));
        }
        return Record;
    }

} // namespace

TEST(CandidateRegistry, NormalizesProtocolNamesAndBuildsBinding)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("HTTP", MakeHttpBinding));

    Composition::CandidateDefinition Candidate;
    Candidate.Id = 11;
    Candidate.Name = "http-entry";
    Candidate.Protocol = "http";

    const auto Binding = Registry.Build(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Id, 11);
    EXPECT_EQ(Binding->Spec.Name, "http-entry");
    EXPECT_EQ(Binding->Spec.Protocol, Prism::Contract::ProtocolType::Http);
}

TEST(TrusttunnelCandidate, FailureResultPreservesTypedCodeAndNativeCause)
{
    const auto Native = std::make_error_code(std::errc::timed_out);
    const Prism::Fault::Failure Failure{Prism::Fault::Code::Timeout, Native};

    Prism::Recognition::CarrierAcceptResult Result;
    Result.Metadata.Carrier = "trusttunnel";
    Composition::Detail::SetTrusttunnelFailure(Result, Failure);

    EXPECT_EQ(Result.Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(Result.NativeError.value(), Native.value());
    EXPECT_STREQ(Result.NativeError.category().name(), Native.category().name());
    EXPECT_FALSE(Result.Transport);
    EXPECT_EQ(Result.Metadata.Carrier, "trusttunnel");
}

TEST(CandidateRegistry, DoesNotResolveRetiredShadowsocksName)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("ss2022", MakeHttpBinding));

    Composition::CandidateDefinition Candidate;
    Candidate.Id = 12;
    Candidate.Protocol = "shadowsocks";

    EXPECT_TRUE(Registry.Has("SS2022"));
    EXPECT_FALSE(Registry.Build(Candidate).has_value());
    Candidate.Protocol = "ss2022";
    EXPECT_TRUE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, RejectsDuplicateNormalizedProtocol)
{
    Composition::CandidateRegistry Registry;

    EXPECT_TRUE(Registry.Register("http", MakeHttpBinding));
    EXPECT_FALSE(Registry.Register("HTTP", MakeHttpBinding));
}

TEST(CandidateRegistry, DoesNotMergeDistinctRegisteredNames)
{
    Composition::CandidateRegistry Registry;

    EXPECT_TRUE(Registry.Register("shadowsocks", MakeHttpBinding));
    EXPECT_TRUE(Registry.Register("SS2022", MakeHttpBinding));
    EXPECT_FALSE(Registry.Register("ss2022", MakeHttpBinding));
}

TEST(CandidateRegistry, FactoryOwnsRegisteredBuilders)
{
    Composition::CandidateBuilder Factory;
    {
        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.Register("http", MakeHttpBinding));
        Factory = Registry.MakeFactory();
    }

    Composition::CandidateDefinition Candidate;
    Candidate.Id = 13;
    Candidate.Protocol = "http";

    EXPECT_TRUE(Factory);
    EXPECT_TRUE(Factory(Candidate).has_value());
}

TEST(CandidateRegistry, MissingProtocolReturnsNoBinding)
{
    Composition::CandidateRegistry Registry;
    Composition::CandidateDefinition Candidate;
    Candidate.Protocol = "vless";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
    EXPECT_FALSE(Registry.Has("vless"));
}

TEST(CandidateRegistry, RegistersCoreProtocolFactories)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(Registry.RegisterConfiguredProvider(
        "socks5",
        Composition::ProviderCandidateInputs{
            Prism::Composition::Provider::BoundInstance{
                "socks5", Prism::Contract::ProtocolType::Socks5,
                Prism::Testing::MakeSocks5Binding({})},
            {}}));
    ASSERT_TRUE(Registry.RegisterConfigured("vless", MakeVlessBinding));
    ASSERT_TRUE(Registry.RegisterConfigured("trojan", MakeTrojanBinding));
    ASSERT_TRUE(Registry.RegisterConfigured("vmess", MakeVmessBinding));
    ASSERT_TRUE(Registry.RegisterConfiguredProvider(
        "ss2022",
        Composition::ProviderCandidateInputs{
            Prism::Composition::Provider::BoundInstance{
                "ss2022", Prism::Contract::ProtocolType::Shadowsocks,
                Prism::Testing::MakeSs2022Binding(
                    Prism::Shadowsocks2022::ServerConfig{Prism::Testing::Ss2022FixturePsk})},
            {}}));

    std::array<Composition::CandidateDefinition, 6> Candidates{
        Composition::CandidateDefinition{1, "http", "http", 0, 0, false},
        Composition::CandidateDefinition{2, "socks5", "socks5", 0, 0, false},
        Composition::CandidateDefinition{3, "vless", "vless", 0, 0, false},
        Composition::CandidateDefinition{4, "trojan", "trojan", 0, 0, false},
        Composition::CandidateDefinition{5, "vmess", "vmess", 0, 0, false},
        Composition::CandidateDefinition{6, "ss2022", "ss2022", 0, 0, false},
    };
    Candidates[0].ProtocolId = "http";
    Candidates[1].ProtocolId = "socks5";
    Candidates[2].ProtocolId = "vless";
    Candidates[3].ProtocolId = "trojan";
    Candidates[4].ProtocolId = "vmess";
    Candidates[5].ProtocolId = "ss2022";

    for (const auto &Candidate : Candidates)
    {
        const auto Binding = Registry.Build(Candidate);
        ASSERT_TRUE(Binding.has_value()) << Candidate.Protocol;
        EXPECT_EQ(Binding->Spec.Id, Candidate.Id);
        EXPECT_TRUE(Binding->Accept);
        EXPECT_TRUE(Binding->Spec.Inspect);
        EXPECT_TRUE(Binding->Spec.Commit);
    }
}

TEST(CandidateRegistry, ComposesRegisteredCarrierWithCoreCandidate)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(RegisterDefaultCarrier(Registry, "native"));

    Composition::CandidateDefinition Candidate{17, "native-http", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "native";
    Candidate.ServerNames = {"example.com"};
    Candidate.Alpn = {"h2"};

    const auto Binding = Registry.Build(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Kind, Core::CandidateKind::TlsCarrier);
    EXPECT_EQ(Binding->Spec.Protocol, Prism::Contract::ProtocolType::Http);
    EXPECT_EQ(Binding->Spec.Scheme, "native");
    EXPECT_TRUE(Binding->Accept);
}

TEST(CandidateRegistry, RejectsUnregisteredCarrierInsteadOfPassthrough)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));

    Composition::CandidateDefinition Candidate{18, "missing-carrier", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "reality";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
    EXPECT_FALSE(Registry.RegisterTlsCarrier(
        {Prism::Composition::Protocol::ProviderCategory::TlsCarrier,
            Prism::Composition::Protocol::CarrierKind::TrustTunnel},
        "trusttunnel", MakeCarrierRegistration()));
}

TEST(CandidateRegistry, RejectsUnknownConfiguredCarrierId)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(RegisterDefaultCarrier(Registry, "native"));

    Composition::CandidateDefinition Candidate{21, "unknown-id", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "native";
    Candidate.CarrierId = "carrier-missing";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, RejectsSchemeMismatchFromPrebuiltTlsBinding)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register(
        "http",
        [](const auto &Candidate) -> std::optional<Composition::CandidateBinding>
        {
            auto Binding = Composition::CandidateFactory::MakeHttp(
                Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority, Candidate.Tier,
                                              Candidate.Fallback},
                Prism::Testing::MakeHttp1Binding());
            Binding.Spec.Kind = Core::CandidateKind::TlsCarrier;
            Binding.Spec.Scheme = "reality";
            return Binding;
        }));

    Composition::CandidateDefinition Candidate{19, "mismatch", "http", 0, 0, false};
    Candidate.Scheme = "native";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, FactoryOwnsCarrierBuilders)
{
    Composition::CandidateBuilder Factory;
    {
        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
        ASSERT_TRUE(RegisterDefaultCarrier(Registry, "native"));
        Factory = Registry.MakeFactory();
    }

    Composition::CandidateDefinition Candidate{20, "owned", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "native";
    const auto Binding = Factory(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Kind, Core::CandidateKind::TlsCarrier);
    EXPECT_EQ(Binding->Spec.Scheme, "native");
}

TEST(CandidateRegistry, RejectsEchForRegisteredNonNativeCarrier)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(RegisterDefaultCarrier(Registry, "ws"));

    Composition::CandidateDefinition Candidate{23, "ws-ech", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "ws";
    Candidate.ServerNames = {"edge.example"};
    Candidate.Alpn = {"h2"};
    const auto Binding = Registry.Build(Candidate);
    ASSERT_TRUE(Binding.has_value());

    const auto Record = MakeEchClientHello("edge.example");
    const auto Bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(Record.data()), Record.size());
    const auto [ParseError, Features] = Core::ParseClientHelloProgress(Bytes);
    ASSERT_EQ(ParseError, Prism::Error::None);
    ASSERT_TRUE(Features.HasEch);
    Prism::Recognition::ProbeBuffer Buffer(64 * 1024,
        std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{64U * 1024U, 8U}));
    ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Record.data(), Record.size())));

    EXPECT_EQ(Binding->Spec.Inspect(Buffer.Snapshot()), Core::MatchState::Rejected);
}
