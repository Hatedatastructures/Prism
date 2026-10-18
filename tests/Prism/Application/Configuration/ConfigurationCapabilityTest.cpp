/**
 * @file ConfigurationCapabilityTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfigurationTestSupport.hpp"

TEST(PrismTask3ProtocolBindingCapability, ParserAllowsProtocolAndCarrierBeforeSnapshotFreeze)
    {
        const auto Json = MakeConfigurationJson(NativeProtocol, NativeCarrier, {});
        const auto Parsed = Parser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        ASSERT_EQ(Parsed->Protocols.size(), 1U);
        ASSERT_EQ(Parsed->Carriers.size(), 1U);
        EXPECT_EQ(Parsed->Protocols.front().Builtin, "socks5");
        EXPECT_EQ(Parsed->Carriers.front().Builtin, "native");
    }

TEST(PrismTask3ProtocolBindingCapability, GenerationRequiresSnapshotForConfiguredProtocol)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(MakeProtocolConfiguration("http"));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

TEST(PrismTask3ProtocolBindingCapability, GenerationRequiresSnapshotForConfiguredCarrier)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Carriers.push_back(MakeNativeCarrierConfiguration("native"));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

TEST(PrismTask3ProtocolBindingCapability, RejectsUnknownProtocolBuiltin)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(MakeProtocolConfiguration("unregistered"));
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

TEST(PrismTask3ProtocolBindingCapability, RejectsUnknownCarrierBuiltin)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Carriers.push_back(
            MakeNativeCarrierConfiguration("unregistered-carrier"));
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

TEST(PrismTask3ProtocolBindingCapability, RejectsDisabledProtocolBuiltin)
    {
        StaticBuiltinOptions RegistryOptions;
        RegistryOptions.Disabled.push_back({"protocol", "http"});
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(MakeProtocolConfiguration("http"));
        Options.Builtins = MakeStaticBuiltinSnapshot(RegistryOptions);
        ASSERT_NE(Options.Builtins, nullptr);

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

TEST(PrismTask3ProtocolBindingCapability, RejectsHttpUdpBindingWithoutDescriptorDatagram)
    {
        auto Protocol = MakeProtocolConfiguration("http");
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(Protocol);
        Prism::Contract::ProtocolBindingConfiguration Binding;
        Binding.Id = "binding-http-udp";
        Binding.ProtocolId = Protocol.Id;
        Binding.TcpEnabled = false;
        Binding.UdpEnabled = true;
        Options.Configuration.ProtocolBindings.push_back(std::move(Binding));
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);
        ASSERT_TRUE(Options.Builtins->Capabilities().Contains(Capability::Datagram));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].UdpEnabled");
    }

TEST(PrismTask3ProtocolBindingCapability, RejectsHttpMuxWithoutDescriptorMultiplex)
    {
        auto Protocol = MakeProtocolConfiguration("http");
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(Protocol);
        Prism::Contract::ProtocolBindingConfiguration Binding;
        Binding.Id = "binding-http-mux";
        Binding.ProtocolId = Protocol.Id;
        Binding.TcpEnabled = true;
        Binding.UdpEnabled = false;
        Binding.MuxModes = {"Smux"};
        Options.Configuration.ProtocolBindings.push_back(std::move(Binding));
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);
        ASSERT_TRUE(Options.Builtins->Capabilities().Contains(Capability::Multiplex));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].MuxModes");
    }

TEST(PrismTask3ProtocolBindingCapability, AcceptsShadowsocks2022AliasForSs2022Descriptor)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(
            MakeProtocolConfiguration("shadowsocks2022"));
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        EXPECT_EQ(Result.value()->Configuration().Protocols.front().Builtin, "shadowsocks2022");
        const auto Entries = Result.value()->Builtins()->Entries();
        const auto Ss2022 = std::find_if(Entries.begin(), Entries.end(), [](const auto &Entry)
        {
            return Entry.Descriptor.Kind.Value() == "protocol" &&
                   Entry.Descriptor.Name.Value() == "ss2022";
        });
        ASSERT_NE(Ss2022, Entries.end());
    }

TEST(PrismTask3ProtocolBindingCapability, AcceptsSocks5UdpFromItsDescriptor)
    {
        auto Protocol = MakeProtocolConfiguration("socks5");
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(Protocol);
        Prism::Contract::ProtocolBindingConfiguration Binding;
        Binding.Id = "binding-socks5-udp";
        Binding.ProtocolId = Protocol.Id;
        Binding.TcpEnabled = false;
        Binding.UdpEnabled = true;
        Options.Configuration.ProtocolBindings.push_back(std::move(Binding));
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
    }

TEST(PrismTask3ProtocolBindingCapability, PreservesTrustedCapabilitiesAndPinsSnapshot)
    {
        Registry RegistryValue({.InitialCapabilities = CapabilitySet{Capability::Core}});
        Prism::Composition::Builtin::BuiltinDescriptor Descriptor;
        Descriptor.Kind = Prism::KindId::From("protocol");
        Descriptor.Name = Prism::NameId::From("trusted");
        Descriptor.Provides = CapabilitySet{Capability::Multiplex};
        Descriptor.Requires = CapabilitySet{Capability::Core};
        bool CallbackInvoked = false;
        Descriptor.Callback = [&CallbackInvoked](
                                 const Prism::Composition::Builtin::BuiltinRequest &)
            -> Prism::Foundation::Expected<void>
        {
            CallbackInvoked = true;
            return {};
        };
        ASSERT_TRUE(RegistryValue.Register(std::move(Descriptor)));
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        ASSERT_TRUE(Frozen);
        auto Snapshot = *Frozen;
        const auto SnapshotIdentity = Snapshot->Identity();

        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(MakeProtocolConfiguration("trusted"));
        Options.Builtins = Snapshot;
        const auto Result = GenerationBuilder::Build(std::move(Options));
        Snapshot.reset();

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        EXPECT_TRUE(Result.value()->Capabilities().Contains(Capability::Multiplex));
        ASSERT_NE(Result.value()->Builtins(), nullptr);
        EXPECT_EQ(Result.value()->Builtins()->Identity(), SnapshotIdentity);
        EXPECT_FALSE(CallbackInvoked);
    }

TEST(PrismTask3ProtocolBindingCapability, PreservesWebsocketAliasForWsDescriptor)
    {
        const auto Json = MakeConfigurationJson(NativeProtocol, WebSocketCarrier, {});
        const auto Parsed = Parser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        auto Configuration = *Parsed;
        Configuration.Carriers.front().Builtin = "websocket";
        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
    }

