/**
 * @file ConfigurationGenerationTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfigurationTestSupport.hpp"

TEST(PrismTask3Generation, RequiresFrozenSnapshotForConfiguredBuiltins)
    {
        const auto Json = ReplaceFirst(
            std::string(ValidJson), "\"Builtins\": [],",
            "\"Builtins\": [{\"Id\":\"builtin-no-snapshot\",\"Kind\":\"protocol\","
            "\"Name\":\"core-only\",\"Requires\":[],\"Provides\":[]}],");
        const auto Parsed = ConfigurationParser::ParseJson(Json);
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Builtins[0]");
    }

TEST(PrismTask3Generation, PinsImmutableGenerationsAcrossSuccessfulReload)
    {
        GenerationBuildOptions InitialOptions;
        InitialOptions.Configuration = ParseValid();
        InitialOptions.Builtins = MakeBuiltinSnapshot(CapabilitySet{Capability::Core});
        InitialOptions.Generation = Prism::GenerationId{1};
        const auto Initial = GenerationBuilder::Build(std::move(InitialOptions));
        ASSERT_TRUE(Initial.has_value()) << Initial.error().Message;

        GenerationPublication Publication;
        auto InitialToken = Publication.Prepare({}, *Initial, {});
        ASSERT_TRUE(InitialToken.has_value());
        ASSERT_TRUE(Publication.Publish(*InitialToken));
        const auto Pinned = *Initial;

        ReloadRequest Request;
        Request.BaseGeneration = (*Initial)->Id();
        Request.Configuration = ParseValid();
        Request.Configuration.Runtime.WorkerCount = 3;
        Request.Builtins = MakeBuiltinSnapshot(CapabilitySet{Capability::Core});

        ReloadCoordinator Coordinator;
        const auto Reloaded = Coordinator.Prepare(*Initial, std::move(Request));

        ASSERT_TRUE(Reloaded.has_value()) << Reloaded.error().Message;
        EXPECT_EQ(Publication.Current()->Id(), Prism::GenerationId{1});
        EXPECT_EQ(Pinned->Id(), Prism::GenerationId{1});
        EXPECT_EQ(Pinned->Configuration().Runtime.WorkerCount, 2U);
        auto CandidateToken = Publication.Prepare(*Initial, *Reloaded, {});
        ASSERT_TRUE(CandidateToken.has_value());
        EXPECT_EQ(Publication.Current()->Id(), Prism::GenerationId{1});
        ASSERT_TRUE(Publication.Publish(*CandidateToken));
        EXPECT_EQ(Publication.Current()->Id(), Prism::GenerationId{2});
        EXPECT_EQ((*Reloaded)->Configuration().Runtime.WorkerCount, 3U);
    }

TEST(PrismTask3Generation, ReloadFailurePreservesTheOldGeneration)
    {
        GenerationBuildOptions InitialOptions;
        InitialOptions.Configuration = ParseValid();
        InitialOptions.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        InitialOptions.Generation = Prism::GenerationId{7};
        const auto Initial = GenerationBuilder::Build(std::move(InitialOptions));
        ASSERT_TRUE(Initial.has_value()) << Initial.error().Message;

        GenerationPublication Publication;
        auto InitialToken = Publication.Prepare({}, *Initial, {});
        ASSERT_TRUE(InitialToken.has_value());
        ASSERT_TRUE(Publication.Publish(*InitialToken));
        ReloadRequest Request;
        Request.BaseGeneration = (*Initial)->Id();
        Request.Configuration = ParseValid();
        Request.Configuration.Runtime.WorkerCount = 0;
        Request.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        ReloadCoordinator Coordinator;
        const auto Reloaded = Coordinator.Prepare(*Initial, std::move(Request));

        ASSERT_FALSE(Reloaded.has_value());
        EXPECT_EQ(Reloaded.error().Code, ConfigurationErrorCode::InvalidValue);
        ASSERT_NE(Publication.Current(), nullptr);
        EXPECT_EQ(Publication.Current()->Id(), Prism::GenerationId{7});
        EXPECT_EQ((*Initial)->Configuration().Runtime.WorkerCount, 2U);
    }

TEST(PrismTask3Generation, RejectsUnknownProtocolBuiltinAgainstFrozenSnapshot)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"unknown-protocol"});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

TEST(PrismTask3Generation, RejectsDisabledProtocolBuiltin)
    {
        auto RegistryValue = Prism::Composition::Builtin::MakeStaticBuiltinRegistry();
        Prism::Composition::Builtin::StaticBuiltinOptions BuiltinOptions;
        BuiltinOptions.Disabled.push_back({"protocol", "socks5"});
        const auto Registration = Prism::Composition::Builtin::RegisterProtocolBuiltins(
            RegistryValue, BuiltinOptions);
        ASSERT_TRUE(Registration);
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        ASSERT_TRUE(Frozen);

        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5"});
        Options.Builtins = *Frozen;

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

TEST(PrismTask3Generation, RejectsProtocolBuiltinRegisteredUnderCarrierKind)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5"});
        Options.Builtins = MakeDescriptorSnapshot({
            "carrier", "socks5", CapabilitySet{Capability::Stream}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

TEST(PrismTask3Generation, RequiresFrozenSnapshotForConfiguredProtocol)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5"});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

TEST(PrismTask3Generation, RejectsUnknownCarrierBuiltinAgainstFrozenSnapshot)
    {
        const auto Parsed = ConfigurationParser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

TEST(PrismTask3Generation, RejectsCarrierBuiltinRegisteredUnderProtocolKind)
    {
        const auto Parsed = ConfigurationParser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "native", CapabilitySet{Capability::Stream, Capability::Tls}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

TEST(PrismTask3Generation, RequiresFrozenSnapshotForConfiguredCarrier)
    {
        const auto Parsed = ConfigurationParser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

TEST(PrismTask3Generation, RejectsTcpBindingWithoutDescriptorStream)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5", true, false, {}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "socks5", CapabilitySet{Capability::Datagram},
            CapabilitySet{Capability::Stream}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].TcpEnabled");
    }

TEST(PrismTask3Generation, RejectsUdpBindingWithoutDescriptorDatagramOrQuic)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5", false, true, {}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "socks5", CapabilitySet{Capability::Stream},
            CapabilitySet{Capability::Datagram}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].UdpEnabled");
    }

TEST(PrismTask3Generation, RejectsMuxBindingWithoutDescriptorMultiplex)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5", true, false, {"Smux"}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "socks5", CapabilitySet{Capability::Stream, Capability::Datagram},
            CapabilitySet{Capability::Multiplex}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].MuxModes");
    }

TEST(PrismTask3Generation, RejectsUnimplementedPhysicalMuxProfiles)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5", true, false, {"4C64S"}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "socks5",
            CapabilitySet{Capability::Stream, Capability::Datagram, Capability::Multiplex}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].MuxModes[0]");
    }

TEST(PrismTask3Generation, AcceptsH2MuxWhenProtocolProvidesMultiplex)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5", true, false, {"H2Mux"}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "socks5",
            CapabilitySet{Capability::Stream, Capability::Datagram, Capability::Multiplex}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
    }

TEST(PrismTask3Generation, AcceptsQuicProtocolDescriptorForUdpBinding)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"hysteria2", false, true, {}});
        Options.Configuration.Protocols.back().Quic =
            Prism::Contract::ProtocolConfiguration::QuicOptions{
                "h3", "quic.example", "secret/quic/password", 32, 64};
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "hysteria2", CapabilitySet{Capability::Quic}, {}});
        Options.SecretResolver = [](std::string_view Reference) -> std::optional<std::string>
        {
            return Reference == "secret/quic/password"
                       ? std::optional<std::string>{"quic-password"}
                       : std::nullopt;
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
    }

TEST(PrismTask3Generation, RejectsTcpForQuicOnlyDescriptor)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"hysteria2", true, false, {}});
        Options.Configuration.Protocols.back().Quic =
            Prism::Contract::ProtocolConfiguration::QuicOptions{
                "h3", "quic.example", "secret/quic/password", 32, 64};
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "hysteria2", CapabilitySet{Capability::Quic}, {}});
        Options.SecretResolver = [](std::string_view Reference) -> std::optional<std::string>
        {
            return Reference == "secret/quic/password"
                       ? std::optional<std::string>{"quic-password"}
                       : std::nullopt;
        };
        ASSERT_NE(Options.Builtins, nullptr);
        const auto *Descriptor = Options.Builtins->Find(Prism::BuiltinId{1});
        ASSERT_NE(Descriptor, nullptr);
        EXPECT_TRUE(Descriptor->Descriptor.Provides.Contains(Capability::Stream));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].TcpEnabled");
    }

TEST(PrismTask3Generation, ResolvesShadowsocks2022AliasToSs2022)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"shadowsocks2022", false, true, {}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "ss2022", CapabilitySet{Capability::Stream, Capability::Datagram}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        ASSERT_EQ((*Result)->Configuration().Protocols.size(), 1U);
        EXPECT_EQ((*Result)->Configuration().Protocols.front().Builtin, "shadowsocks2022");
        const auto *Descriptor = (*Result)->Builtins()->Find(Prism::BuiltinId{1});
        ASSERT_NE(Descriptor, nullptr);
        EXPECT_EQ(Descriptor->Descriptor.Name.Value(), "ss2022");
    }

TEST(PrismTask3Generation, ResolvesCarrierFromFrozenSnapshot)
    {
        const auto Parsed = ConfigurationParser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;
        Options.Builtins = MakeDescriptorSnapshot({
            "carrier", "native", CapabilitySet{Capability::Tls, Capability::Stream}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        ASSERT_EQ((*Result)->Builtins()->Size(), 1U);
    }

TEST(PrismTask3Generation, PreservesDescriptorCapabilitiesAndPinsFrozenSnapshot)
    {
        auto Snapshot = MakeDescriptorSnapshot({
            "protocol", "capability-source", CapabilitySet{Capability::Datagram}, {}});
        ASSERT_NE(Snapshot, nullptr);
        std::weak_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> SnapshotPin = Snapshot;

        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"capability-source", false, true, {}});
        Options.Builtins = Snapshot;
        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        EXPECT_TRUE((*Result)->Capabilities().Contains(Capability::Datagram));
        EXPECT_EQ((*Result)->Builtins(), Snapshot);
        Snapshot.reset();
        EXPECT_FALSE(SnapshotPin.expired());
        EXPECT_NE((*Result)->Builtins(), nullptr);
    }

TEST(PrismQuicConfiguration, BuildsHysteriaCredentialContextPerGeneration)
    {
        auto Configuration = ParseValid();
        Configuration.Protocols.clear();
        Configuration.Protocols.push_back(Prism::Contract::ProtocolConfiguration{
            "protocol-hysteria2",
            "hysteria2",
            "hysteria2",
            {},
            Prism::Contract::ProtocolConfiguration::QuicOptions{
                "h3", "quic.example", "secret/hysteria/password", 32, 64}});
        Configuration.ProtocolBindings.clear();
        Prism::Contract::ProtocolBindingConfiguration Binding;
        Binding.Id = "binding-hysteria2";
        Binding.ProtocolId = "protocol-hysteria2";
        Binding.TcpEnabled = false;
        Binding.UdpEnabled = true;
        Configuration.ProtocolBindings.push_back(std::move(Binding));

        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeStaticBuiltinSnapshot();
        Options.SecretResolver = [](std::string_view Reference) -> std::optional<std::string>
        {
            if (Reference == "secret/hysteria/password")
            {
                return "hysteria-password";
            }
            return std::nullopt;
        };
        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        ASSERT_TRUE((*Result)->Configuration().Protocols.front().Quic.has_value());
        EXPECT_EQ((*Result)->Configuration().Protocols.front().Quic->Alpn, "h3");
        EXPECT_EQ((*Result)->LookupSecret("secret/hysteria/password").size(), 17U);
    }

TEST(PrismQuicConfiguration, RejectsMissingOrWrongHysteriaCredentialAndAlpn)
    {
        auto Configuration = ParseValid();
        Configuration.Protocols.clear();
        Configuration.Protocols.push_back(Prism::Contract::ProtocolConfiguration{
            "protocol-hysteria2", "hysteria2", "hysteria2", {},
            Prism::Contract::ProtocolConfiguration::QuicOptions{
                "h2", "quic.example", "secret/hysteria/password", 32, 64}});
        Configuration.ProtocolBindings.clear();
        Prism::Contract::ProtocolBindingConfiguration Binding;
        Binding.Id = "binding-hysteria2";
        Binding.ProtocolId = "protocol-hysteria2";
        Binding.TcpEnabled = false;
        Binding.UdpEnabled = true;
        Configuration.ProtocolBindings.push_back(std::move(Binding));

        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeStaticBuiltinSnapshot();
        Options.SecretResolver = [](std::string_view) -> std::optional<std::string>
        {
            return std::nullopt;
        };
        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Quic.Alpn");
    }

