/**
 * @file ProfileBootstrapTest.cpp
 * @brief cold recognition definition 到 Prism Profile 的 Composition 接线测试
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Composition/Recognition/CandidateRegistry.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Test/Prism/Runtime/Session/AdmissionSupport.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;

    [[nodiscard]] auto MakeCandidateOptions(const Composition::CandidateDefinition &Candidate)
        -> Composition::CandidateOptions
    {
        Composition::CandidateOptions Options;
        Options.Id = Candidate.Id;
        Options.Name = Candidate.Name;
        Options.Priority = Candidate.Priority;
        Options.Tier = Candidate.Tier;
        Options.Fallback = Candidate.Fallback;
        Options.BindingId = Candidate.BindingId;
        Options.UdpEnabled = Candidate.UdpEnabled;
        return Options;
    }

    [[nodiscard]] auto MakeCarrierAccept() -> Composition::CarrierAcceptFn
    {
        return [](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            Core::CarrierAcceptResult Result;
            Result.Transport = std::move(Input.Inbound);
            co_return Result;
        };
    }

    [[nodiscard]] auto RegisterTestCarrier(Composition::CandidateRegistry &Registry,
        const std::string_view Scheme, std::string Id = {}) -> bool
    {
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Scheme);
        if (!Descriptor)
        {
            return false;
        }
        Composition::CandidateRegistry::CarrierRegistration Registration{
            Descriptor->Slot(), MakeCarrierAccept(), {}, false};
        return Registry.RegisterTlsCarrier(Descriptor->Slot(), std::move(Id),
            std::move(Registration));
    }

    auto MakeBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        Composition::CandidateBinding Binding;
        Binding.Spec.Id = Candidate.Id;
        Binding.Spec.Name = Candidate.Name;
        Binding.Spec.Protocol = Prism::Contract::ProtocolType::Http;
        Binding.Spec.MinimumBytes = 1;
        Binding.Spec.FirstBytes = {'C'};
        Binding.Spec.Inspect = [](const Core::ProbeSnapshot &Snapshot)
        {
            if (Snapshot.Empty())
            {
                return Core::MatchState::NeedMore;
            }
            return Core::MatchState::Structural;
        };
        Binding.Spec.Commit = [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
        {
            Core::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Binding.Accept = std::make_shared<Prism::Testing::StreamFactory>(
            [](Prism::Contract::StreamAcceptInput Input)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            {
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
                co_return Plane;
            });
        return Binding;
    }

    [[nodiscard]] auto MakeHttpCandidateBinding(const Core::CandidateId Id)
        -> std::optional<Composition::CandidateBinding>
    {
        return MakeBinding(Composition::CandidateDefinition{Id, "session-http", "http", 0, 0, false});
    }

    auto MakeTlsRouteBinding(const Composition::CandidateDefinition &Candidate,
                             std::vector<std::string> &FactoryServerNames)
        -> std::optional<Composition::CandidateBinding>
    {
        FactoryServerNames = Candidate.ServerNames;
        Composition::TlsCandidateOptions Options;
        Options.Id = Candidate.Id;
        Options.Name = Candidate.Name;
        Options.Scheme = Candidate.Scheme;
        Options.ServerNames = Candidate.ServerNames;
        Options.Alpn = Candidate.Alpn;
        Options.Fallback = Candidate.Fallback;
        auto Tls = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            MakeCarrierAccept());
        Composition::CandidateBinding Binding;
        Binding.Spec = std::move(Tls.Spec);
        Binding.Accept = std::make_shared<Prism::Testing::StreamFactory>(
            [](Prism::Contract::StreamAcceptInput Input)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            {
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
                co_return Plane;
            });
        return Binding;
    }

    auto RejectCandidateFactory(const Composition::CandidateDefinition &)
        -> std::optional<Composition::CandidateBinding>
    {
        return std::nullopt;
    }

    auto MakeMismatchedCarrierBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        auto Binding = MakeBinding(Candidate);
        if (!Binding)
        {
            return std::nullopt;
        }
        Binding->Spec.Kind = Core::CandidateKind::TlsCarrier;
        Binding->Spec.Scheme = "reality";
        return Binding;
    }

    auto MakeQuicBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        auto Binding = MakeBinding(Candidate);
        if (!Binding)
        {
            return std::nullopt;
        }
        Binding->Spec.Protocol = Prism::Contract::ProtocolType::Hysteria2;
        Binding->Spec.Kind = Core::CandidateKind::QuicCarrier;
        return Binding;
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

    auto MakeTlsClientHello(std::string_view ServerName) -> std::vector<std::byte>
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
        const auto SniExtension = MakeExtension(0x0000, Sni);
        const auto AlpnExtension = MakeExtension(0x0010, AlpnPayload);
        const auto VersionsExtension = MakeExtension(0x002B, {0x02, 0x03, 0x04});
        std::vector<std::uint8_t> Extensions;
        for (const auto &Extension : {SniExtension, AlpnExtension, VersionsExtension})
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

    auto RunNaturalCoro(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
                      [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

} // namespace

TEST(ProfileBootstrap, BuildsConfiguredProfileAndResolverFromDefinition)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 7;
    Config.Candidates.push_back(Composition::CandidateDefinition{7, "http-entry", "http", 3, 1, false});

    const auto Result = Composition::ProfileBuilder::Build(Config, MakeBinding);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->Mode(), Core::RecognitionMode::Configured);
    EXPECT_EQ(Result->Profile->CandidateCount(), 1U);
    EXPECT_EQ(Result->Profile->CandidateIdAt(0), 7U);
    EXPECT_TRUE(static_cast<bool>(Result->Resolve(7)));

    Prism::Runtime::SessionOptions Options;
    Options.Services->Profile = Result->Profile;
    Options.Services->ResolveCandidate = Result->Resolver;
    EXPECT_EQ(Options.Services->Profile->CandidateIdAt(0), 7U);
    EXPECT_TRUE(static_cast<bool>(Options.Services->ResolveCandidate(7)));
    EXPECT_TRUE(static_cast<bool>(Options.Services->ResolveCandidate(7)));
}

TEST(ProfileBootstrap, PreservesMixedTrialCandidatesAndRoutes)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Config.Budget.MaxCandidates = 2;
    Config.DefaultCandidate = 9;
    Config.Candidates.push_back(Composition::CandidateDefinition{2, "first", "http", 2, 0, false});
    Config.Candidates.push_back(Composition::CandidateDefinition{9, "second", "http", 1, 1, true});
    Config.Routes.emplace_back("*.example.com", 2);

    const auto Result = Composition::ProfileBuilder::Build(Config, MakeBinding);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->Mode(), Core::RecognitionMode::MixedTrial);
    ASSERT_EQ(Result->Profile->CandidateCount(), 2U);
    EXPECT_EQ(Result->Profile->CandidateIdAt(0), 2U);
    EXPECT_EQ(Result->Profile->CandidateIdAt(1), 9U);
    ASSERT_TRUE(Result->Profile->LookupRoute("api.example.com").has_value());
    EXPECT_EQ(Result->Profile->LookupRoute("api.example.com").value(), 2U);
    ASSERT_TRUE(Result->Profile->LookupRoute("unknown.example.net").has_value());
    EXPECT_EQ(Result->Profile->LookupRoute("unknown.example.net").value(), 9U);
}

TEST(ProfileBootstrap, DerivesTlsServerNamesFromRecognitionRoutes)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Composition::CandidateDefinition Candidate{11, "edge-vless", "vless", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(Candidate);
    Config.Routes.emplace_back("edge.example", Candidate.Id);

    std::vector<std::string> FactoryServerNames;
    const auto Result = Composition::ProfileBuilder::Build(
        Config,
        [&FactoryServerNames](const auto &FactoryCandidate)
        { return MakeTlsRouteBinding(FactoryCandidate, FactoryServerNames); });

    ASSERT_TRUE(Result.has_value());
    ASSERT_EQ(FactoryServerNames.size(), 1U);
    EXPECT_EQ(FactoryServerNames.front(), "edge.example");
}

TEST(ProfileBootstrap, AppliesRoutePatternAlongsideConfiguredServerNames)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Composition::CandidateDefinition Candidate{24, "ws-route", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "ws";
    Candidate.ServerNames = {"configured.example"};
    Candidate.Alpn = {"h2"};
    Config.Candidates.push_back(Candidate);
    Config.Routes.emplace_back("route.example", Candidate.Id);

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeBinding));
    ASSERT_TRUE(RegisterTestCarrier(Registry, "ws"));

    std::vector<std::string> FactoryServerNames;
    const auto Result = Composition::ProfileBuilder::Build(
        Config,
        [&Registry, &FactoryServerNames](const auto &FactoryCandidate)
            -> std::optional<Composition::CandidateBinding>
        {
            FactoryServerNames = FactoryCandidate.ServerNames;
            return Registry.Build(FactoryCandidate);
        });

    ASSERT_TRUE(Result.has_value());
    ASSERT_EQ(FactoryServerNames.size(), 2U);
    EXPECT_NE(std::find(FactoryServerNames.begin(), FactoryServerNames.end(),
                        "configured.example"), FactoryServerNames.end());
    EXPECT_NE(std::find(FactoryServerNames.begin(), FactoryServerNames.end(),
                        "route.example"), FactoryServerNames.end());

    const auto Handle = Result->Profile->FindCandidate(Candidate.Id);
    ASSERT_TRUE(Handle.IsValid());
    const auto Record = MakeTlsClientHello("route.example");
    const auto ClientHelloBytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(Record.data()), Record.size());
    const auto [ParseError, Features] = Core::ParseClientHelloProgress(ClientHelloBytes);
    ASSERT_EQ(ParseError, Prism::Error::None);
    EXPECT_EQ(Features.ServerName, "route.example");
    ASSERT_TRUE(Features.HasAlpn);
    auto Bytes = std::make_shared<Prism::Memory::BytePool>(
        Prism::Memory::BytePoolOptions{64U, 2U});
    Prism::Recognition::ProbeBuffer Buffer(64 * 1024, std::move(Bytes));
    ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Record.data(), Record.size())));

    EXPECT_EQ(Handle.Inspect(Buffer.Snapshot()), Core::MatchState::Structural);
}

TEST(ProfileBootstrap, DoesNotInferConfiguredCandidateForDeterministicMode)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Deterministic;
    Config.Candidates.push_back(Composition::CandidateDefinition{7, "deterministic", "http", 0, 0, false});

    const auto Result = Composition::ProfileBuilder::Build(Config, MakeBinding);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->Mode(), Core::RecognitionMode::Deterministic);
    EXPECT_EQ(Result->Profile->ConfiguredCandidate(), Core::InvalidCandidate);
}

TEST(ProfileBootstrap, RejectsMissingCandidateFactoryResult)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 3;
    Config.Candidates.push_back(Composition::CandidateDefinition{3, "missing", "http", 0, 0, false});

    const auto Result = Composition::ProfileBuilder::Build(
        Config, [](const auto &) -> std::optional<Composition::CandidateBinding> { return std::nullopt; });

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
}

TEST(ProfileBootstrap, BuildsProfileThroughCandidateRegistry)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 14;
    Config.Candidates.push_back(Composition::CandidateDefinition{14, "registry-http", "HTTP", 0, 0, false});

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("http", MakeBinding));

    const auto Result = Composition::ProfileBuilder::Build(Config, Registry.MakeFactory());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->ConfiguredCandidate(), 14U);
    EXPECT_TRUE(static_cast<bool>(Result->Resolve(14)));
}

TEST(ProfileBootstrap, BuildsAnyTlsProfileThroughCandidateRegistry)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 22;
    Config.Candidates.push_back(
        Composition::CandidateDefinition{22, "registry-anytls", "anytls", 0, 0, false});
    Config.Candidates.back().ProtocolId = "anytls";

    Composition::CandidateRegistry Registry;
    Prism::Anytls::ServerConfig AnyTlsConfig;
    AnyTlsConfig.Password = "profile-test-password";
    auto AnyTlsOptions = Prism::Anytls::IngressOptions{
        .Configuration = std::move(AnyTlsConfig),
        .Streams = {.Egress = Prism::Testing::UnavailableEgress()}};
    ASSERT_TRUE(Registry.RegisterConfigured("anytls",
        [AnyTlsOptions = std::move(AnyTlsOptions)](const auto &Candidate)
            -> std::optional<Composition::CandidateBinding>
        {
            return Composition::CandidateFactory::MakeAnytls(
                MakeCandidateOptions(Candidate), AnyTlsOptions);
        }));

    const auto Result = Composition::ProfileBuilder::Build(Config, Registry.MakeFactory());

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    const auto Handle = Result->Profile->FindCandidate(22);
    ASSERT_TRUE(Handle.IsValid());
    EXPECT_EQ(Handle.Protocol(), Prism::Contract::ProtocolType::AnyTls);
    EXPECT_TRUE(static_cast<bool>(Result->Resolve(22)));
}

TEST(ProfileBootstrap, RejectsQuicCandidateInTcpProfile)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 15;
    Config.Candidates.push_back(Composition::CandidateDefinition{15, "hysteria2", "hysteria2", 0, 0, false});

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("hysteria2", MakeQuicBinding));

    const auto Result = Composition::ProfileBuilder::Build(Config, Registry.MakeFactory());

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::QuicCandidateRequiresGateway);
}

TEST(ProfileBootstrap, RejectsQuicCandidateBeforeCallingFactory)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Config.Candidates.push_back(
        Composition::CandidateDefinition{16, "hysteria", "hysteria2", 0, 0, false});

    bool FactoryCalled = false;
    const auto Result = Composition::ProfileBuilder::Build(Config, RejectCandidateFactory);

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::QuicCandidateRequiresGateway);
    EXPECT_FALSE(FactoryCalled);
}

TEST(ProfileBootstrap, PreservesConfiguredOuterSchemeMetadata)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 16;
    Composition::CandidateDefinition Candidate{16, "secured", "http", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(std::move(Candidate));

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("http", MakeBinding));
    ASSERT_TRUE(RegisterTestCarrier(Registry, "native"));

    const auto Result = Composition::ProfileBuilder::Build(Config, Registry.MakeFactory());

    ASSERT_TRUE(Result.has_value());
    const auto Handle = Result->Profile->FindCandidate(16);
    EXPECT_EQ(Handle.Scheme(), "native");
}

TEST(ProfileBootstrap, DoesNotMergeDifferentOuterMetadata)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Config.Budget.MaxCandidates = 4;

    Composition::CandidateDefinition First{41, "shared-first", "http", 1, 0, false};
    First.ProtocolId = "http";
    First.Scheme = "ws";
    First.ServerNames = {"same.example"};
    First.Alpn = {"h2"};
    First.CarrierId = "shared-ws";
    Composition::CandidateDefinition Second{42, "shared-second", "http", 9, 2, true};
    Second.ProtocolId = "http";
    Second.Scheme = "ws";
    Second.ServerNames = {"same.example"};
    Second.Alpn = {"h2"};
    Second.CarrierId = "shared-ws";
    Config.Candidates.push_back(First);
    Config.Candidates.push_back(Second);

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeBinding));
    ASSERT_TRUE(RegisterTestCarrier(Registry, "ws", "shared-ws"));

    const auto Result = Composition::ProfileBuilder::Build(Config, Registry.MakeFactory());

    ASSERT_TRUE(Result.has_value());
    ASSERT_EQ(Result->Profile->CandidateCount(), 2U);
    const auto FirstHandle = Result->Profile->FindCandidate(First.Id);
    const auto SecondHandle = Result->Profile->FindCandidate(Second.Id);
    ASSERT_TRUE(FirstHandle.IsValid());
    ASSERT_TRUE(SecondHandle.IsValid());
    EXPECT_EQ(FirstHandle.Priority(), First.Priority);
    EXPECT_EQ(FirstHandle.Tier(), First.Tier);
    EXPECT_EQ(SecondHandle.Priority(), Second.Priority);
    EXPECT_EQ(SecondHandle.Tier(), Second.Tier);
    EXPECT_FALSE(Result->Profile->FallbackCandidates().Test(First.Id));
    EXPECT_TRUE(Result->Profile->FallbackCandidates().Test(Second.Id));
}

TEST(ProfileBootstrap, RejectsSchemeWithoutCarrierBinding)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 19;
    Composition::CandidateDefinition Candidate{19, "raw", "http", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(std::move(Candidate));

    const auto Result = Composition::ProfileBuilder::Build(Config, MakeBinding);

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
}

TEST(ProfileBootstrap, RejectsMismatchedCarrierScheme)
{
    Composition::RecognitionDefinition Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 21;
    Composition::CandidateDefinition Candidate{21, "mismatch", "http", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(std::move(Candidate));

    const auto Result = Composition::ProfileBuilder::Build(Config, MakeMismatchedCarrierBinding);

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
}

TEST(ProfileBootstrap, BuildsProfileIntoOwnedSessionServices)
{
    auto Binding = MakeHttpCandidateBinding(4);
    ASSERT_TRUE(Binding);
    auto Built = Composition::ProfileBuilder::Build(std::move(*Binding));
    ASSERT_TRUE(Built);
    auto Services = std::make_shared<Prism::Runtime::SessionServices>();
    Services->Profile = Built->Profile;
    Services->ResolveCandidate = std::move(Built->Resolver);
    Services->RelayIdleTimeout = std::chrono::milliseconds(1234);
    Prism::Runtime::Session Session({.Services = Services});
    EXPECT_EQ(Session.Services()->Profile->CandidateIdAt(0), 4U);
    EXPECT_TRUE(Session.Services()->ResolveCandidate(4));
    EXPECT_EQ(Session.Services()->RelayIdleTimeout, std::chrono::milliseconds(1234));
}

TEST(ProfileBootstrap, RejectsUnsupportedProtocolBeforeFactoryInvocation)
{
    Composition::RecognitionDefinition Config;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 5;
    Config.Candidates.push_back(Composition::CandidateDefinition{5, "unknown", "future-proto", 0, 0, false});

    bool Invoked = false;
    const auto Result = Composition::ProfileBuilder::Build(
        Config,
        [&Invoked](const auto &) -> std::optional<Composition::CandidateBinding>
        {
            Invoked = true;
            return std::nullopt;
        });

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
    EXPECT_FALSE(Invoked);
}

TEST(ProfileBootstrap, ListenerFactoryKeepsRecognitionOwner)
{
    auto Binding = MakeHttpCandidateBinding(6);
    ASSERT_TRUE(Binding);
    auto Built = Composition::ProfileBuilder::Build(std::move(*Binding));
    ASSERT_TRUE(Built);
    auto Services = std::make_shared<Prism::Runtime::SessionServices>();
    Services->Profile = Built->Profile;
    Services->ResolveCandidate = std::move(Built->Resolver);
    const std::weak_ptr<Prism::Runtime::SessionServices> Weak = Services;
    auto Factory = [Services](Prism::Runtime::SessionAdmission)
    { return std::make_shared<Prism::Runtime::Session>(Prism::Runtime::SessionOptions{.Services = Services}); };
    Services.reset();
    auto Session = Factory(Prism::Runtime::SessionAdmission{});
    ASSERT_TRUE(Session);
    EXPECT_FALSE(Weak.expired());
    EXPECT_TRUE(Session->Services()->ResolveCandidate(6));
}

TEST(ProfileBootstrap, ListenerUsesExplicitConnectionBudget)
{
    Net::io_context Io;
    Prism::Runtime::TcpListener::Options Options;
    Options.Executor = Io.get_executor();
    Options.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
        Prism::GenerationId{1});
    Options.MaxConnections = 7;
    Prism::Runtime::TcpListener Listener(std::move(Options));
    EXPECT_EQ(Listener.MaxConnections(), 7U);
}

TEST(ProfileBootstrap, StartsListenerOnExplicitNumericEndpoint)
{
    Net::io_context Io;
    Prism::Runtime::TcpListener::Options Options;
    Options.Executor = Io.get_executor();
    Options.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
        Prism::GenerationId{1});
    Prism::Runtime::TcpListener Listener(std::move(Options));
    Prism::Fault::Code Result = Prism::Fault::Code::GenericError;
    std::uint16_t BoundPort = 0;
    RunNaturalCoro(Io, [&]() -> Net::awaitable<void>
    {
        Result = co_await Listener.Start({Net::ip::address_v4::loopback(), 0});
        if (Result == Prism::Fault::Code::Success) BoundPort = Listener.LocalEndpoint().port();
        Listener.Stop();
    }());
    EXPECT_EQ(Result, Prism::Fault::Code::Success);
    EXPECT_NE(BoundPort, 0U);
}
