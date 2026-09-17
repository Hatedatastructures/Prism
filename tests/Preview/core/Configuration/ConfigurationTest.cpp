/**
 * @file ConfigurationTest.cpp
 * @brief PrismPreview 配置模型、生成与热重载契约测试。
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <Preview/Application/Configuration/Configuration.hpp>
#include <Preview/Composition/Builtin/Registry.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>

namespace
{

    using Preview::Application::Configuration::BuiltinConfiguration;
    using Preview::Application::Configuration::CarrierConfiguration;
    using Preview::Application::Configuration::ConfigurationErrorCode;
    using Preview::Application::Configuration::ConfigurationGeneration;
    using Preview::Application::Configuration::ConfigurationStore;
    using Preview::Application::Configuration::GenerationBuildOptions;
    using Preview::Application::Configuration::GenerationBuilder;
    using Preview::Application::Configuration::NativeTlsOptions;
    using Preview::Application::Configuration::ProtocolConfiguration;
    using Preview::Application::Configuration::ProtocolBindingConfiguration;
    using Preview::Application::Configuration::ProtocolConfiguration;
    using Preview::Application::Configuration::PreviewConfiguration;
    using Preview::Application::Configuration::RealityOptions;
    using Preview::Application::Configuration::RestlsOptions;
    using Preview::Application::Configuration::ShadowTlsOptions;
    using Preview::Application::Configuration::TrustTunnelOptions;
    using Preview::Application::Configuration::Parser;
    using Preview::Application::Configuration::ReloadCoordinator;
    using Preview::Application::Configuration::ReloadRequest;
    using Preview::Composition::Builtin::Capability;
    using Preview::Composition::Builtin::CapabilitySet;
    using Preview::Composition::Builtin::BuiltinDescriptor;
    using Preview::Composition::Builtin::FreezeRequest;
    using Preview::Composition::Builtin::Registry;
    using Preview::Composition::Builtin::StaticBuiltinOptions;

    constexpr std::string_view ValidJson = R"json(
{
  "SchemaVersion": 1,
  "Runtime": {
    "WorkerCount": 2,
    "RequiredCapabilities": [],
    "SessionTimeout": 30000
  },
  "Listeners": {
    "Tcp": [{"Id": "tcp-main", "Address": "127.0.0.1", "Port": 1080, "Timeout": 5000}],
    "Udp": [{"Id": "udp-main", "Address": "127.0.0.1", "Port": 1081, "Timeout": 5000}],
    "Quic": [{"Id": "quic-main", "Address": "127.0.0.1", "Port": 1081, "Timeout": 5000}],
    "Timeout": 5000
  },
  "Builtins": [],
  "Protocols": [],
  "Carriers": [],
  "ProtocolBindings": [],
  "Accounts": [{"Id": "local", "SecretRef": "", "Credential": "local-token"}],
  "Routes": [],
  "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
  "Logging": {
    "Level": "Info",
    "Directory": "logs",
    "FileName": "preview.log",
    "Console": false,
    "RotateBytes": 67108864,
    "RotateFiles": 8,
    "FlushIntervalMs": 250
  },
  "Trace": {
    "IncludeCorrelation": true,
    "IncludeWorker": true,
    "IncludeSession": true,
    "IncludeStream": false
  },
  "Statistics": {"Enabled": true, "Interval": 1000},
  "Operations": {"Enabled": true, "Endpoint": "127.0.0.1:9090", "Timeout": 1000},
  "HotReload": {"Enabled": true, "AckTimeout": 5000},
  "Shutdown": {"Timeout": 5000}
}
)json";

    auto ReplaceFirst(std::string Value, std::string_view From, std::string_view To) -> std::string
    {
        const auto Position = Value.find(From);
        if (Position != std::string::npos)
        {
            Value.replace(Position, From.size(), To);
        }
        return Value;
    }

    auto MakeBuiltinSnapshot(const CapabilitySet Capabilities)
        -> std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot>
    {
        Registry RegistryValue({.InitialCapabilities = Capabilities});
        auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        return Frozen ? *Frozen : nullptr;
    }

    auto MakeStaticBuiltinSnapshot(const StaticBuiltinOptions &Options = {})
        -> std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot>
    {
        auto RegistryValue = Preview::Composition::Builtin::MakeStaticBuiltinRegistry();
        if (!Preview::Composition::Builtin::RegisterStaticBuiltins(RegistryValue, Options))
        {
            return nullptr;
        }
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        return Frozen ? *Frozen : nullptr;
    }

    auto MakeProtocolConfiguration(std::string Builtin) -> ProtocolConfiguration
    {
        ProtocolConfiguration Protocol;
        Protocol.Id = "protocol-" + Builtin;
        Protocol.Name = Builtin;
        Protocol.Builtin = std::move(Builtin);
        return Protocol;
    }

    auto MakeNativeCarrierConfiguration(std::string Builtin) -> CarrierConfiguration
    {
        CarrierConfiguration Carrier;
        Carrier.Id = "carrier-" + Builtin;
        Carrier.Name = Builtin;
        Carrier.Builtin = std::move(Builtin);
        Carrier.Match.ServerNames = {"example.com"};
        Carrier.Match.Alpn = {"h2"};
        Carrier.Match.Priority = 7;
        Carrier.Match.Fallback = true;
        Carrier.Options = NativeTlsOptions{"cert.pem", "key.pem"};
        return Carrier;
    }

    struct BuiltinDescriptorFixture final
    {
        std::string_view Kind;
        std::string_view Name;
        CapabilitySet Provides{};
        CapabilitySet InitialCapabilities{};
    };

    auto MakeDescriptorSnapshot(const BuiltinDescriptorFixture &Fixture)
        -> std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot>
    {
        Registry RegistryValue({.InitialCapabilities = Fixture.InitialCapabilities});
        BuiltinDescriptor Descriptor;
        Descriptor.Kind = Preview::KindId::From(Fixture.Kind);
        Descriptor.Name = Preview::NameId::From(Fixture.Name);
        Descriptor.Provides = Fixture.Provides;
        Descriptor.Callback = [](const Preview::Composition::Builtin::BuiltinRequest &)
            -> Preview::Foundation::Expected<void> { return {}; };
        if (!RegistryValue.Register(std::move(Descriptor)))
        {
            return nullptr;
        }
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        return Frozen ? *Frozen : nullptr;
    }

    struct ProtocolBindingFixture final
    {
        std::string_view Builtin;
        bool TcpEnabled{true};
        bool UdpEnabled{false};
        std::vector<std::string> MuxModes;
    };

    auto ParseValid() -> PreviewConfiguration;

    auto MakeBoundProtocolConfiguration(const ProtocolBindingFixture &Fixture)
        -> PreviewConfiguration
    {
        auto Configuration = ParseValid();
        Configuration.Protocols.push_back(ProtocolConfiguration{
            "protocol-test", std::string(Fixture.Builtin), std::string(Fixture.Builtin), {}});

        ProtocolBindingConfiguration Binding;
        Binding.Id = "binding-test";
        Binding.ProtocolId = "protocol-test";
        Binding.TcpEnabled = Fixture.TcpEnabled;
        Binding.UdpEnabled = Fixture.UdpEnabled;
        Binding.MuxModes = Fixture.MuxModes;
        Configuration.ProtocolBindings.push_back(std::move(Binding));
        return Configuration;
    }

    auto ParseValid() -> Preview::Application::Configuration::PreviewConfiguration
    {
        const auto Parsed = Parser::ParseJson(ValidJson);
        EXPECT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        return *Parsed;
    }

    auto MakeConfigurationJson(std::string_view Protocols,
                               std::string_view Carriers,
                               std::string_view Bindings) -> std::string
    {
        auto Json = ReplaceFirst(
            std::string(ValidJson),
            "\"Protocols\": [],",
            "\"Protocols\": [" + std::string(Protocols) + "],");
        Json = ReplaceFirst(
            std::move(Json),
            "\"Carriers\": [],\n  \"ProtocolBindings\": [],",
            "\"Carriers\": [" + std::string(Carriers) + "],\n  \"ProtocolBindings\": [" +
                std::string(Bindings) + "],");
        return Json;
    }

    constexpr std::string_view NativeCarrier = R"json(
{
  "Id": "carrier-native",
  "Name": "native-tls",
  "Builtin": "native",
  "Requires": [],
  "Match": {
    "ServerNames": ["example.com"],
    "Alpn": ["h2", "http/1.1"],
    "Priority": 7,
    "Fallback": true
  },
  "Options": {
    "Type": "NativeTls",
    "CertificateFile": "cert.pem",
    "PrivateKeyFile": "key.pem"
  }
}
)json";

    constexpr std::string_view AnyTlsProtocol = R"json(
{
  "Id": "protocol-anytls",
  "Name": "anytls",
  "Builtin": "anytls",
  "Requires": []
}
)json";

    constexpr std::string_view NativeProtocol = R"json(
{
  "Id": "protocol-socks5",
  "Name": "socks5",
  "Builtin": "socks5",
  "Requires": []
}
)json";

    constexpr std::string_view NativeBinding = R"json(
{
  "Id": "binding-socks5",
  "ProtocolId": "protocol-socks5",
  "CarrierId": "carrier-native",
  "TcpEnabled": true,
  "UdpEnabled": true,
  "MuxModes": ["Smux", "Yamux"],
  "Priority": 9,
  "Recognition": {
    "Pattern": "example.com",
    "Domain": "example.com",
    "Fallback": true
  }
}
)json";

    struct CarrierBindingFixture final
    {
        std::string Id;
        std::string CarrierId;
        std::int32_t Priority{0};
        bool TcpEnabled{true};
        bool UdpEnabled{false};
    };

    constexpr std::string_view CarrierBindingTemplate = R"json(
{
  "Id": "@BindingId@",
  "ProtocolId": "protocol-socks5",
  "CarrierId": "@CarrierId@",
  "TcpEnabled": @TcpEnabled@,
  "UdpEnabled": @UdpEnabled@,
  "MuxModes": [],
  "Priority": @Priority@,
  "Recognition": {}
}
)json";

    auto MakeCarrierBindingJson(const CarrierBindingFixture &Fixture) -> std::string
    {
        auto Json = ReplaceFirst(
            std::string(CarrierBindingTemplate), "@BindingId@", Fixture.Id);
        Json = ReplaceFirst(std::move(Json), "@CarrierId@", Fixture.CarrierId);
        Json = ReplaceFirst(
            std::move(Json), "@TcpEnabled@", Fixture.TcpEnabled ? "true" : "false");
        Json = ReplaceFirst(
            std::move(Json), "@UdpEnabled@", Fixture.UdpEnabled ? "true" : "false");
        return ReplaceFirst(std::move(Json), "@Priority@", std::to_string(Fixture.Priority));
    }

    constexpr std::string_view RealityCarrier = R"json(
{
  "Id": "carrier-reality",
  "Name": "reality",
  "Builtin": "reality",
  "Requires": [],
  "Match": {"ServerNames": ["www.microsoft.com"], "Alpn": ["h2"], "Priority": 7},
  "Options": {
    "Type": "Reality",
    "HandshakeTarget": "www.microsoft.com:443",
    "ServerNames": ["www.microsoft.com"],
    "PrivateKeyRef": "secret/reality/private-key",
    "ShortIds": ["45587ac66ce007e4"]
  }
}
)json";

    constexpr std::string_view ShadowTlsCarrier = R"json(
{
  "Id": "carrier-shadowtls",
  "Name": "shadowtls",
  "Builtin": "shadowtls",
  "Requires": [],
  "Match": {"ServerNames": ["www.apple.com"]},
  "Options": {
    "Type": "ShadowTls",
    "Version": 3,
    "PasswordSecretRef": "secret/shadowtls/password",
    "HandshakeDest": "www.apple.com:443",
    "ServerNames": ["www.apple.com"],
    "StrictMode": true,
    "HandshakeTimeoutMs": 5000
  }
}
)json";

    constexpr std::string_view TrustTunnelCarrier = R"json(
{
  "Id": "carrier-trusttunnel",
  "Name": "trusttunnel",
  "Builtin": "trusttunnel",
  "Requires": [],
  "Options": {
    "Type": "TrustTunnel",
    "ServerNames": ["www.amazon.com"],
    "CertificateFile": "cert.pem",
    "PrivateKeySecretRef": "secret/trusttunnel/private-key",
    "PasswordSecretRef": "secret/trusttunnel/password",
    "Network": "Both",
    "Congestion": "Bbr",
    "HandshakeTimeoutMs": 5000,
    "IdleTimeoutMs": 30000
  }
}
)json";

    constexpr std::string_view RestlsCarrier = R"json(
{
  "Id": "carrier-restls",
  "Name": "restls",
  "Builtin": "restls",
  "Requires": [],
  "Options": {
    "Type": "Restls",
    "ServerNames": ["www.example.com"],
    "Host": "www.example.com:443",
    "PasswordSecretRef": "secret/restls/password",
    "VersionHint": "tls13",
    "RestlsScript": "300?100<1",
    "HandshakeTimeoutMs": 5000
  }
}
)json";

    constexpr std::string_view WebSocketCarrier = R"json(
{
  "Id": "carrier-websocket",
  "Name": "websocket",
  "Builtin": "ws",
  "Requires": [],
  "Options": {"Type": "WebSocket", "Path": "/ws", "Host": "www.example.com"}
}
)json";

    TEST(PreviewTask4Configuration, ParsesTypedCarrierMatchAndNativeTlsOptions)
    {
        const auto Json = MakeConfigurationJson(NativeProtocol, NativeCarrier, {});
        const auto Parsed = Parser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        ASSERT_EQ(Parsed->Carriers.size(), 1U);
        const auto &Carrier = Parsed->Carriers.front();
        EXPECT_EQ(Carrier.Match.ServerNames, std::vector<std::string>({"example.com"}));
        EXPECT_EQ(Carrier.Match.Alpn, std::vector<std::string>({"h2", "http/1.1"}));
        EXPECT_EQ(Carrier.Match.Priority, 7);
        EXPECT_TRUE(Carrier.Match.Fallback);
        ASSERT_TRUE(std::holds_alternative<NativeTlsOptions>(Carrier.Options));
        const auto &Options = std::get<NativeTlsOptions>(Carrier.Options);
        EXPECT_EQ(Options.CertificateFile, "cert.pem");
        EXPECT_EQ(Options.PrivateKeyFile, "key.pem");
    }

    TEST(PreviewTask4Configuration, ParsesTypedFacadeCarrierOptions)
    {
    constexpr std::string_view TypedCarriers = R"json(
{
  "Id": "carrier-reality",
  "Name": "reality",
  "Builtin": "reality",
  "Requires": [],
  "Match": {"ServerNames": ["www.microsoft.com"]},
  "Options": {
    "Type": "Reality",
    "HandshakeTarget": "www.microsoft.com:443",
    "ServerNames": ["www.microsoft.com"],
    "PrivateKeyRef": "secret/reality/private-key",
    "ShortIds": ["45587ac66ce007e4"]
  }
},
{
  "Id": "carrier-shadowtls",
  "Name": "shadowtls",
  "Builtin": "shadowtls",
  "Requires": [],
  "Match": {"ServerNames": ["www.apple.com"]},
  "Options": {
    "Type": "ShadowTls",
    "Version": 3,
    "PasswordSecretRef": "secret/shadowtls/password",
    "HandshakeDest": "www.apple.com:443",
    "ServerNames": ["www.apple.com"],
    "StrictMode": true,
    "HandshakeTimeoutMs": 5000
  }
},
{
  "Id": "carrier-restls",
  "Name": "restls",
  "Builtin": "restls",
  "Requires": [],
  "Match": {"ServerNames": ["www.nvidia.com"]},
  "Options": {
    "Type": "Restls",
    "ServerNames": ["www.nvidia.com"],
    "Host": "www.nvidia.com:443",
    "PasswordSecretRef": "secret/restls/password",
    "VersionHint": "tls13",
    "RestlsScript": "300?100<1",
    "HandshakeTimeoutMs": 5000
  }
},
{
  "Id": "carrier-websocket",
  "Name": "websocket",
  "Builtin": "ws",
  "Requires": [],
  "Match": {"ServerNames": ["www.ws.example.com"]},
  "Options": {
    "Type": "WebSocket",
    "Path": "/ws",
    "Host": "www.example.com"
  }
},
{
  "Id": "carrier-xhttp",
  "Name": "xhttp",
  "Builtin": "xhttp",
  "Requires": [],
  "Match": {"ServerNames": ["www.xhttp.example.com"]},
  "Options": {
    "Type": "Xhttp",
    "Path": "/xhttp",
    "Host": "www.example.com",
    "Mode": "StreamOne"
  }
},
{
  "Id": "carrier-gun",
  "Name": "gun",
  "Builtin": "gun",
  "Requires": [],
  "Match": {"ServerNames": ["www.gun.example.com"]},
  "Options": {
    "Type": "Gun",
    "ServerNames": ["www.example.com"],
    "Mode": "Grpc",
    "Path": "/GunService/Tun",
    "ServiceName": "GunService"
  }
}
)json";
        const auto Json = MakeConfigurationJson(NativeProtocol, TypedCarriers, {});
        const auto Parsed = Parser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        ASSERT_EQ(Parsed->Carriers.size(), 6U);
        EXPECT_TRUE(std::holds_alternative<Preview::Application::Configuration::RealityOptions>(
            Parsed->Carriers[0].Options));
        EXPECT_TRUE(std::holds_alternative<Preview::Application::Configuration::ShadowTlsOptions>(
            Parsed->Carriers[1].Options));
        EXPECT_TRUE(std::holds_alternative<Preview::Application::Configuration::RestlsOptions>(
            Parsed->Carriers[2].Options));
        EXPECT_TRUE(std::holds_alternative<Preview::Application::Configuration::WebSocketOptions>(
            Parsed->Carriers[3].Options));
        EXPECT_TRUE(std::holds_alternative<Preview::Application::Configuration::XhttpOptions>(
            Parsed->Carriers[4].Options));
        EXPECT_TRUE(std::holds_alternative<Preview::Application::Configuration::GunOptions>(
            Parsed->Carriers[5].Options));
        EXPECT_EQ(std::get<Preview::Application::Configuration::RealityOptions>(
                      Parsed->Carriers[0].Options)
                      .HandshakeTarget,
                  "www.microsoft.com:443");
        EXPECT_EQ(std::get<Preview::Application::Configuration::RealityOptions>(
                      Parsed->Carriers[0].Options)
                      .PrivateKeyRef,
                  "secret/reality/private-key");
        EXPECT_EQ(std::get<Preview::Application::Configuration::ShadowTlsOptions>(
                      Parsed->Carriers[1].Options)
                      .PasswordSecretRef,
                  "secret/shadowtls/password");
        const auto &Gun = std::get<Preview::Application::Configuration::GunOptions>(
            Parsed->Carriers[5].Options);
        EXPECT_EQ(Gun.Path, "/GunService/Tun");
        EXPECT_EQ(Gun.ServiceName, "GunService");
        EXPECT_EQ(Gun.Mode, "Grpc");
        const auto &Xhttp = std::get<Preview::Application::Configuration::XhttpOptions>(
            Parsed->Carriers[4].Options);
        EXPECT_EQ(Xhttp.Path, "/xhttp");
        EXPECT_EQ(Xhttp.Host, "www.example.com");
        EXPECT_EQ(Xhttp.Mode, "StreamOne");
    }

    TEST(PreviewTask4Configuration, AcceptsXhttpModes)
    {
        constexpr std::string_view XhttpOnly = R"json(
{
  "Id": "carrier-xhttp",
  "Name": "xhttp",
  "Builtin": "xhttp",
  "Requires": [],
  "Match": {"ServerNames": ["www.xhttp.example.com"]},
  "Options": {
    "Type": "Xhttp",
    "Path": "/xhttp",
    "Host": "www.example.com",
    "Mode": "StreamOne"
  }
}
)json";
        const auto Parsed = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, XhttpOnly, {}),
             .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        for (const auto Mode : {"StreamOne", "StreamUp", "PacketUp"})
        {
            auto Configuration = *Parsed;
            std::get<Preview::Application::Configuration::XhttpOptions>(
                Configuration.Carriers[0].Options)
                .Mode = Mode;
            const auto Result = Parser::Validate(
                Preview::Application::Configuration::ValidationRequest{
                    Configuration,
                    Preview::Application::Configuration::ValidationOptions{
                        .CheckSecrets = false, .CheckCapabilities = false}});
            EXPECT_TRUE(Result.has_value()) << Mode;
        }

        auto InvalidConfiguration = *Parsed;
        std::get<Preview::Application::Configuration::XhttpOptions>(
            InvalidConfiguration.Carriers[0].Options)
            .Mode = "Unknown";
        const auto InvalidResult = Parser::Validate(
            Preview::Application::Configuration::ValidationRequest{
                InvalidConfiguration,
                Preview::Application::Configuration::ValidationOptions{
                    .CheckSecrets = false, .CheckCapabilities = false}});
        ASSERT_FALSE(InvalidResult.has_value());
        EXPECT_EQ(InvalidResult.error().Path, "Carriers[0].Options.Mode");
        EXPECT_EQ(InvalidResult.error().Code, ConfigurationErrorCode::InvalidValue);
    }

    TEST(PreviewTask4Configuration, RejectsLegacyRealityFieldNames)
    {
        const auto LegacyTarget = ReplaceFirst(
            std::string(RealityCarrier), "\"HandshakeTarget\"", "\"Dest\"");
        const auto LegacyPrivateKeyRef = ReplaceFirst(
            std::string(RealityCarrier), "\"PrivateKeyRef\"", "\"PrivateKeySecretRef\"");
        const auto TargetResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, LegacyTarget, {}),
             .Options = {.CheckSecrets = false}});
        const auto PrivateKeyResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, LegacyPrivateKeyRef, {}),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(TargetResult.has_value());
        EXPECT_EQ(TargetResult.error().Code, ConfigurationErrorCode::UnknownField);
        ASSERT_FALSE(PrivateKeyResult.has_value());
        EXPECT_EQ(PrivateKeyResult.error().Code, ConfigurationErrorCode::UnknownField);
    }

    TEST(PreviewTask4Configuration, ParsesProtocolBindingAndRecognitionRoute)
    {
        const auto Json = MakeConfigurationJson(NativeProtocol, NativeCarrier, NativeBinding);
        const auto Parsed = Parser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        ASSERT_EQ(Parsed->ProtocolBindings.size(), 1U);
        const auto &Binding = Parsed->ProtocolBindings.front();
        EXPECT_EQ(Binding.ProtocolId, "protocol-socks5");
        ASSERT_TRUE(Binding.CarrierId.has_value());
        EXPECT_EQ(*Binding.CarrierId, "carrier-native");
        EXPECT_TRUE(Binding.TcpEnabled);
        EXPECT_TRUE(Binding.UdpEnabled);
        EXPECT_EQ(Binding.MuxModes, std::vector<std::string>({"Smux", "Yamux"}));
        EXPECT_EQ(Binding.Priority, 9);
        EXPECT_EQ(Binding.Recognition.Pattern, "example.com");
        EXPECT_EQ(Binding.Recognition.Domain, "example.com");
        EXPECT_TRUE(Binding.Recognition.Fallback);
    }

    TEST(PreviewTask4Configuration, ParsesTopLevelRecognitionMode)
    {
        const auto Json = ReplaceFirst(
            std::string(ValidJson),
            "  \"ProtocolBindings\": [],",
            "  \"ProtocolBindings\": [],\n  \"Recognition\": {\"Mode\": \"Configured\", \"ConfiguredCandidate\": 1},");
        const auto Parsed = Parser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        EXPECT_EQ(Parsed->Recognition.Mode, "Configured");
        EXPECT_EQ(Parsed->Recognition.ConfiguredCandidate, 1);
    }

    TEST(PreviewTask4Configuration, AllowsAnyTlsAsAProtocolWithoutAnyTlsCarrier)
    {
        constexpr std::string_view AnyTlsBinding = R"json(
{
  "Id": "binding-anytls",
  "ProtocolId": "protocol-anytls",
  "TcpEnabled": true,
  "UdpEnabled": false,
  "MuxModes": [],
  "Priority": 1,
  "Recognition": {}
}
)json";
        const auto Json = MakeConfigurationJson(AnyTlsProtocol, {}, AnyTlsBinding);
        const auto Parsed = Parser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        ASSERT_EQ(Parsed->Protocols.front().Builtin, "anytls");
        EXPECT_TRUE(Parsed->Carriers.empty());
        ASSERT_EQ(Parsed->ProtocolBindings.front().ProtocolId, "protocol-anytls");
        EXPECT_FALSE(Parsed->ProtocolBindings.front().CarrierId.has_value());
    }

    TEST(PreviewTask4Configuration, RejectsTypedBindingContractViolations)
    {
        const auto UnknownField = ReplaceFirst(
            MakeConfigurationJson(NativeProtocol, NativeCarrier, NativeBinding),
            "\"Priority\": 9,",
            "\"Priority\": 9,\n  \"Unknown\": true,");
        const auto DuplicateBinding = MakeConfigurationJson(
            NativeProtocol,
            NativeCarrier,
            std::string(NativeBinding) + "," + std::string(NativeBinding));
        const auto MissingProtocol = MakeConfigurationJson(
            NativeProtocol,
            NativeCarrier,
            ReplaceFirst(std::string(NativeBinding), "protocol-socks5", "missing-protocol"));
        const auto DuplicateProtocolId = MakeConfigurationJson(
            NativeProtocol,
            NativeCarrier,
            ReplaceFirst(std::string(NativeBinding), "binding-socks5", "protocol-socks5"));
        const auto MissingCarrier = MakeConfigurationJson(
            NativeProtocol,
            NativeCarrier,
            ReplaceFirst(std::string(NativeBinding), "carrier-native", "missing-carrier"));
        const auto EmptyCarrier = MakeConfigurationJson(
            NativeProtocol,
            NativeCarrier,
            ReplaceFirst(std::string(NativeBinding), "\"CarrierId\": \"carrier-native\"",
                          "\"CarrierId\": \"\""));
        const auto UnknownMuxMode = MakeConfigurationJson(
            NativeProtocol,
            NativeCarrier,
            ReplaceFirst(std::string(NativeBinding), "[\"Smux\", \"Yamux\"]", "[\"Unknown\"]"));
        const auto AnyTlsCarrier = MakeConfigurationJson(
            NativeProtocol,
            ReplaceFirst(std::string(NativeCarrier), "\"Builtin\": \"native\"",
                          "\"Builtin\": \"anytls\""),
            {});

        const auto UnknownResult = Parser::Parse(
            {.Json = UnknownField, .Options = {.CheckSecrets = false}});
        const auto DuplicateResult = Parser::Parse(
            {.Json = DuplicateBinding, .Options = {.CheckSecrets = false}});
        const auto MissingResult = Parser::Parse(
            {.Json = MissingProtocol, .Options = {.CheckSecrets = false}});
        const auto DuplicateProtocolIdResult = Parser::Parse(
            {.Json = DuplicateProtocolId, .Options = {.CheckSecrets = false}});
        const auto MissingCarrierResult = Parser::Parse(
            {.Json = MissingCarrier, .Options = {.CheckSecrets = false}});
        const auto EmptyResult = Parser::Parse(
            {.Json = EmptyCarrier, .Options = {.CheckSecrets = false}});
        const auto MuxResult = Parser::Parse(
            {.Json = UnknownMuxMode, .Options = {.CheckSecrets = false}});
        const auto AnyTlsResult = Parser::Parse(
            {.Json = AnyTlsCarrier, .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(UnknownResult.has_value());
        EXPECT_EQ(UnknownResult.error().Code, ConfigurationErrorCode::UnknownField);
        ASSERT_FALSE(DuplicateResult.has_value());
        EXPECT_EQ(DuplicateResult.error().Code, ConfigurationErrorCode::DuplicateId);
        ASSERT_FALSE(MissingResult.has_value());
        EXPECT_EQ(MissingResult.error().Code, ConfigurationErrorCode::MissingReference);
        ASSERT_FALSE(DuplicateProtocolIdResult.has_value());
        EXPECT_EQ(DuplicateProtocolIdResult.error().Code, ConfigurationErrorCode::DuplicateId);
        EXPECT_EQ(DuplicateProtocolIdResult.error().Path, "ProtocolBindings[0].Id");
        ASSERT_FALSE(MissingCarrierResult.has_value());
        EXPECT_EQ(MissingCarrierResult.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(MissingCarrierResult.error().Path, "ProtocolBindings[0].CarrierId");
        ASSERT_FALSE(EmptyResult.has_value());
        EXPECT_EQ(EmptyResult.error().Code, ConfigurationErrorCode::InvalidValue);
        ASSERT_FALSE(MuxResult.has_value());
        EXPECT_EQ(MuxResult.error().Code, ConfigurationErrorCode::UnknownMuxMode);
        ASSERT_FALSE(AnyTlsResult.has_value());
        EXPECT_EQ(AnyTlsResult.error().Code, ConfigurationErrorCode::InvalidValue);
    }

    TEST(PreviewConfigPreflight, RejectsCarrierBuiltinConfiguredAsProtocol)
    {
        const auto MisclassifiedProtocol = ReplaceFirst(
            std::string(NativeProtocol), "\"Builtin\": \"socks5\"",
            "\"Builtin\": \"native\"");
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(MisclassifiedProtocol, {}, {}),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

    TEST(PreviewConfigPreflight, RejectsTrustTunnelConfiguredAsCarrier)
    {
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, TrustTunnelCarrier, {}),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

    TEST(PreviewConfigPreflight, RejectsAnyTlsBoundToReality)
    {
        const auto Binding = ReplaceFirst(
            ReplaceFirst(std::string(NativeBinding), "protocol-socks5", "protocol-anytls"),
            "carrier-native", "carrier-reality");
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(AnyTlsProtocol, RealityCarrier, Binding),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].CarrierId");
    }

    TEST(PreviewConfigPreflight, RejectsEqualEffectiveTcpCarrierPriority)
    {
        const auto FirstCarrier = ReplaceFirst(
            std::string(NativeCarrier), "\"Priority\": 7", "\"Priority\": 1");
        auto SecondCarrier = ReplaceFirst(
            std::string(NativeCarrier), "carrier-native", "carrier-native-2");
        SecondCarrier = ReplaceFirst(
            std::move(SecondCarrier), "\"Priority\": 7", "\"Priority\": 2");
        const auto Bindings = MakeCarrierBindingJson(
                                  {"binding-one", "carrier-native", 5, true, false}) +
                              "," + MakeCarrierBindingJson(
                                  {"binding-two", "carrier-native-2", 5, true, false});
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(
                 NativeProtocol, FirstCarrier + "," + SecondCarrier, Bindings),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Carriers[1].Match");
    }

    TEST(PreviewConfigPreflight, AllowsDifferentEffectiveTcpCarrierPriorities)
    {
        const auto FirstCarrier = ReplaceFirst(
            std::string(NativeCarrier), "\"Priority\": 7", "\"Priority\": 1");
        auto SecondCarrier = ReplaceFirst(
            std::string(NativeCarrier), "carrier-native", "carrier-native-2");
        SecondCarrier = ReplaceFirst(
            std::move(SecondCarrier), "\"Priority\": 7", "\"Priority\": 1");
        const auto Bindings = MakeCarrierBindingJson(
                                  {"binding-one", "carrier-native", 5, true, false}) +
                              "," + MakeCarrierBindingJson(
                                  {"binding-two", "carrier-native-2", 6, true, false});
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(
                 NativeProtocol, FirstCarrier + "," + SecondCarrier, Bindings),
             .Options = {.CheckSecrets = false}});

        EXPECT_TRUE(Result.has_value()) << Result.error().Message;
    }

    TEST(PreviewConfigPreflight, IgnoresCarrierSelectorsWithoutTcpBindings)
    {
        const auto SecondCarrier = ReplaceFirst(
            std::string(NativeCarrier), "carrier-native", "carrier-native-2");
        const auto Carriers = std::string(NativeCarrier) + "," + SecondCarrier;
        const auto NoBindingResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, Carriers, {}),
             .Options = {.CheckSecrets = false}});
        const auto UdpBindings = MakeCarrierBindingJson(
                                    {"binding-one", "carrier-native", 5, false, true}) +
                                "," + MakeCarrierBindingJson(
                                    {"binding-two", "carrier-native-2", 5, false, true});
        const auto UdpOnlyResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, Carriers, UdpBindings),
             .Options = {.CheckSecrets = false}});

        EXPECT_TRUE(NoBindingResult.has_value()) << NoBindingResult.error().Message;
        EXPECT_TRUE(UdpOnlyResult.has_value()) << UdpOnlyResult.error().Message;
    }

    TEST(PreviewConfigPreflight, RejectsAmbiguousProtocolRecognitionRoutes)
    {
        const auto SecondBinding = ReplaceFirst(
            std::string(NativeBinding), "binding-socks5", "binding-socks5-2");
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(
                 NativeProtocol, NativeCarrier, std::string(NativeBinding) + "," + SecondBinding),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[1].Recognition");
    }

    TEST(PreviewConfigPreflight, RejectsMalformedCarrierSniAndAlpn)
    {
        const auto BadServerName = ReplaceFirst(
            std::string(NativeCarrier), "example.com", "bad..example.com");
        const auto BadAlpn = ReplaceFirst(
            std::string(NativeCarrier), "\"h2\", \"http/1.1\"", "\"\"");
        const auto ServerNameResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, BadServerName, {}),
             .Options = {.CheckSecrets = false}});
        const auto AlpnResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, BadAlpn, {}),
             .Options = {.CheckSecrets = false}});

        EXPECT_FALSE(ServerNameResult.has_value());
        if (!ServerNameResult)
        {
            EXPECT_EQ(ServerNameResult.error().Path, "Carriers[0].Match.ServerNames[0]");
        }
        EXPECT_FALSE(AlpnResult.has_value());
        if (!AlpnResult)
        {
            EXPECT_EQ(AlpnResult.error().Path, "Carriers[0].Match.Alpn[0]");
        }
    }

    TEST(PreviewConfigPreflight, ValidatesRealityShortIdAndHandshakeTargetFormats)
    {
        const auto BadShortId = ReplaceFirst(
            std::string(RealityCarrier), "45587ac66ce007e4", "abc");
        const auto BadTarget = ReplaceFirst(
            std::string(RealityCarrier), "www.microsoft.com:443", "www.microsoft.com");
        const auto ShortIdResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, BadShortId, {}),
             .Options = {.CheckSecrets = false}});
        const auto TargetResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, BadTarget, {}),
             .Options = {.CheckSecrets = false}});
        const auto EmptyShortId = ReplaceFirst(
            std::string(RealityCarrier), "45587ac66ce007e4", "");
        const auto WildcardRealityName = ReplaceFirst(
            std::string(RealityCarrier),
            "\"ServerNames\": [\"www.microsoft.com\"],\n    \"PrivateKeyRef\"",
            "\"ServerNames\": [\"*.microsoft.com\"],\n    \"PrivateKeyRef\"");
        const auto EmptyShortIdResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, EmptyShortId, {}),
             .Options = {.CheckSecrets = false}});
        const auto WildcardNameResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, WildcardRealityName, {}),
             .Options = {.CheckSecrets = false}});

        EXPECT_FALSE(ShortIdResult.has_value());
        if (!ShortIdResult)
        {
            EXPECT_EQ(ShortIdResult.error().Path, "Carriers[0].Options.ShortIds[0]");
        }
        EXPECT_FALSE(TargetResult.has_value());
        if (!TargetResult)
        {
            EXPECT_EQ(TargetResult.error().Path, "Carriers[0].Options.HandshakeTarget");
        }
        EXPECT_TRUE(EmptyShortIdResult.has_value()) << EmptyShortIdResult.error().Message;
        EXPECT_FALSE(WildcardNameResult.has_value());
        if (!WildcardNameResult)
        {
            EXPECT_EQ(WildcardNameResult.error().Path, "Carriers[0].Options.ServerNames[0]");
        }

        auto NoSniConfiguration = ParseValid();
        CarrierConfiguration NoSniReality;
        NoSniReality.Id = "carrier-reality-no-sni";
        NoSniReality.Name = "reality-no-sni";
        NoSniReality.Builtin = "reality";
        NoSniReality.Options = Preview::Application::Configuration::RealityOptions{
            .HandshakeTarget = "www.microsoft.com:443",
            .ServerNames = {""},
            .PrivateKeyRef = "secret/reality/private-key",
            .ShortIds = {""}};
        NoSniConfiguration.Carriers.push_back(std::move(NoSniReality));
        const auto NoSniResult = Parser::Validate(
            Preview::Application::Configuration::ValidationRequest{
                NoSniConfiguration,
                Preview::Application::Configuration::ValidationOptions{
                    .CheckSecrets = false, .CheckCapabilities = false}});
        EXPECT_TRUE(NoSniResult.has_value()) << NoSniResult.error().Message;
    }

    TEST(PreviewConfigPreflight, RejectsMissingRequiredTypedCarrierFields)
    {
        const auto MissingCertificate = ReplaceFirst(
            std::string(NativeCarrier), "\"CertificateFile\": \"cert.pem\"",
            "\"CertificateFile\": \"\"");
        const auto MissingPrivateKey = ReplaceFirst(
            std::string(NativeCarrier), "\"PrivateKeyFile\": \"key.pem\"",
            "\"PrivateKeyFile\": \"\"");
        const auto MissingRealityTarget = ReplaceFirst(
            std::string(RealityCarrier),
            "\"HandshakeTarget\": \"www.microsoft.com:443\"",
            "\"HandshakeTarget\": \"\"");
        const auto MissingRealityPrivateKeyRef = ReplaceFirst(
            std::string(RealityCarrier),
            "\"PrivateKeyRef\": \"secret/reality/private-key\"",
            "\"PrivateKeyRef\": \"\"");
        const auto MissingRealityShortIds = ReplaceFirst(
            std::string(RealityCarrier), "\"ShortIds\": [\"45587ac66ce007e4\"]",
            "\"ShortIds\": []");
        const auto MissingRestlsScript = ReplaceFirst(
            std::string(RestlsCarrier), "\"RestlsScript\": \"300?100<1\"",
            "\"RestlsScript\": \"\"");
        const auto MissingWebSocketPath = ReplaceFirst(
            std::string(WebSocketCarrier), "\"Path\": \"/ws\"", "\"Path\": \"\"");

        const auto CertificateResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, MissingCertificate, {}),
             .Options = {.CheckSecrets = false}});
        const auto PrivateKeyResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, MissingPrivateKey, {}),
             .Options = {.CheckSecrets = false}});
        const auto RealityTargetResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, MissingRealityTarget, {}),
             .Options = {.CheckSecrets = false}});
        const auto MissingRealityPrivateKeyResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, MissingRealityPrivateKeyRef, {}),
             .Options = {.CheckSecrets = false}});
        const auto UnresolvedRealityPrivateKeyResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, RealityCarrier, {}),
             .Options = {.CheckSecrets = true}});
        const auto RealityShortIdsResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, MissingRealityShortIds, {}),
             .Options = {.CheckSecrets = false}});
        const auto RestlsScriptResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, MissingRestlsScript, {}),
             .Options = {.CheckSecrets = false}});
        const auto WebSocketPathResult = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, MissingWebSocketPath, {}),
             .Options = {.CheckSecrets = false}});

        const auto ExpectMissing = [](const auto &Result, const std::string_view Path)
        {
            ASSERT_FALSE(Result.has_value());
            EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingField);
            EXPECT_EQ(Result.error().Path, Path);
        };
        ExpectMissing(CertificateResult, "Carriers[0].Options.CertificateFile");
        ExpectMissing(PrivateKeyResult, "Carriers[0].Options.PrivateKeyFile");
        ExpectMissing(RealityTargetResult, "Carriers[0].Options.HandshakeTarget");
        ExpectMissing(MissingRealityPrivateKeyResult, "Carriers[0].Options.PrivateKeyRef");
        ExpectMissing(RealityShortIdsResult, "Carriers[0].Options.ShortIds");
        ExpectMissing(RestlsScriptResult, "Carriers[0].Options.RestlsScript");
        ExpectMissing(WebSocketPathResult, "Carriers[0].Options.Path");
        ASSERT_FALSE(UnresolvedRealityPrivateKeyResult.has_value());
        EXPECT_EQ(UnresolvedRealityPrivateKeyResult.error().Code,
                  ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(UnresolvedRealityPrivateKeyResult.error().Path,
                  "Carriers[0].Options.PrivateKeyRef");
    }

    TEST(PreviewConfigPreflight, RejectsMalformedRestlsScript)
    {
        const auto BadScript = ReplaceFirst(
            std::string(RestlsCarrier), "300?100<1", "not-a-script");
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, BadScript, {}),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Path, "Carriers[0].Options.RestlsScript");
    }

    TEST(PreviewConfigPreflight, RejectsMalformedWebSocketPath)
    {
        const auto BadPath = ReplaceFirst(
            std::string(WebSocketCarrier), "\"Path\": \"/ws\"", "\"Path\": \"ws\"");
        const auto Result = Parser::Parse(
            {.Json = MakeConfigurationJson(NativeProtocol, BadPath, {}),
             .Options = {.CheckSecrets = false}});

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Path, "Carriers[0].Options.Path");
    }

    TEST(PreviewConfigPreflight, GenerationBuilderRejectsAmbiguousCarrierRoutes)
    {
        auto Configuration = ParseValid();
        CarrierConfiguration First;
        First.Id = "carrier-native";
        First.Name = "native-tls";
        First.Builtin = "native";
        First.Match.ServerNames = {"example.com"};
        First.Match.Alpn = {"h2"};
        First.Match.Priority = 7;
        First.Match.Fallback = true;
        First.Options = NativeTlsOptions{"cert.pem", "key.pem"};
        auto Second = First;
        Second.Id = "carrier-native-2";
        Configuration.Carriers = {std::move(First), std::move(Second)};
        Preview::Application::Configuration::ProtocolConfiguration Protocol;
        Protocol.Id = "protocol-socks5";
        Protocol.Name = "socks5";
        Protocol.Builtin = "socks5";
        Configuration.Protocols.push_back(Protocol);
        ProtocolBindingConfiguration FirstBinding;
        FirstBinding.Id = "binding-native";
        FirstBinding.ProtocolId = Protocol.Id;
        FirstBinding.CarrierId = "carrier-native";
        FirstBinding.TcpEnabled = true;
        FirstBinding.UdpEnabled = false;
        FirstBinding.Priority = 5;
        auto SecondBinding = FirstBinding;
        SecondBinding.Id = "binding-native-2";
        SecondBinding.CarrierId = "carrier-native-2";
        Configuration.ProtocolBindings = {std::move(FirstBinding), std::move(SecondBinding)};

        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);
        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Carriers[1].Match");
    }

    TEST(PreviewTask3Configuration, ParsesTheAuthoritativePascalCaseSchema)
    {
        const auto Parsed = Parser::ParseJson(ValidJson);

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        EXPECT_EQ(Parsed->SchemaVersion, 1U);
        EXPECT_EQ(Parsed->Runtime.WorkerCount, 2U);
        EXPECT_EQ(Parsed->Listeners.Tcp.front().Port, 1080U);
        EXPECT_EQ(Parsed->Listeners.Udp.front().Port, 1081U);
        EXPECT_EQ(Parsed->Listeners.Quic.front().Port, 1081U);
        EXPECT_EQ(Parsed->Accounts.front().Id, "local");
    }

    TEST(PreviewTaskLoggingConfiguration, ParsesPascalCaseLoggingAndTraceFields)
    {
        const auto Parsed = Parser::ParseJson(ValidJson);

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        EXPECT_EQ(Parsed->Logging.Level, "Info");
        EXPECT_EQ(Parsed->Logging.Directory, "logs");
        EXPECT_EQ(Parsed->Logging.FileName, "preview.log");
        EXPECT_FALSE(Parsed->Logging.Console);
        EXPECT_EQ(Parsed->Logging.RotateBytes, 67108864U);
        EXPECT_EQ(Parsed->Logging.RotateFiles, 8U);
        EXPECT_EQ(Parsed->Logging.FlushIntervalMs, 250U);
        EXPECT_TRUE(Parsed->Trace.IncludeCorrelation);
        EXPECT_TRUE(Parsed->Trace.IncludeWorker);
        EXPECT_TRUE(Parsed->Trace.IncludeSession);
        EXPECT_FALSE(Parsed->Trace.IncludeStream);
    }

    TEST(PreviewTaskLoggingConfiguration, DefaultsUseFileLoggingAndDisableConsole)
    {
        const auto Defaults =
            Preview::Application::Configuration::PreviewConfiguration::Defaults();

        EXPECT_EQ(Defaults.Logging.Level, "Info");
        EXPECT_EQ(Defaults.Logging.Directory, "logs");
        EXPECT_EQ(Defaults.Logging.FileName, "preview.log");
        EXPECT_FALSE(Defaults.Logging.Console);
        EXPECT_EQ(Defaults.Logging.RotateBytes, 67108864U);
        EXPECT_EQ(Defaults.Logging.RotateFiles, 8U);
        EXPECT_EQ(Defaults.Logging.FlushIntervalMs, 250U);
        EXPECT_TRUE(Defaults.Trace.IncludeCorrelation);
        EXPECT_TRUE(Defaults.Trace.IncludeWorker);
        EXPECT_TRUE(Defaults.Trace.IncludeSession);
        EXPECT_FALSE(Defaults.Trace.IncludeStream);
    }

    TEST(PreviewTask3Configuration, RejectsUnknownFieldsAtEverySchemaBoundary)
    {
        const auto UnknownTopLevel = ReplaceFirst(
            std::string(ValidJson), "\n  \"SchemaVersion\": 1,", "\n  \"Unknown\": true,\n  \"SchemaVersion\": 1,");
        const auto UnknownNested = ReplaceFirst(
            std::string(ValidJson), "\"WorkerCount\": 2,", "\"WorkerCount\": 2, \"Unknown\": true,");

        const auto TopResult = Parser::ParseJson(UnknownTopLevel);
        const auto NestedResult = Parser::ParseJson(UnknownNested);

        ASSERT_FALSE(TopResult.has_value());
        EXPECT_EQ(TopResult.error().Code, ConfigurationErrorCode::UnknownField);
        ASSERT_FALSE(NestedResult.has_value());
        EXPECT_EQ(NestedResult.error().Code, ConfigurationErrorCode::UnknownField);
    }

    TEST(PreviewTaskLoggingConfiguration, RejectsUnknownLoggingAndTraceFields)
    {
        const auto UnknownLogging = ReplaceFirst(
            std::string(ValidJson), "\"Level\": \"Info\",",
            "\"Level\": \"Info\", \"Unknown\": true,");
        const auto UnknownTrace = ReplaceFirst(
            std::string(ValidJson), "\"IncludeStream\": false",
            "\"IncludeStream\": false, \"Unknown\": true");

        const auto LoggingResult = Parser::ParseJson(UnknownLogging);
        const auto TraceResult = Parser::ParseJson(UnknownTrace);

        ASSERT_FALSE(LoggingResult.has_value());
        EXPECT_EQ(LoggingResult.error().Code, ConfigurationErrorCode::UnknownField);
        ASSERT_FALSE(TraceResult.has_value());
        EXPECT_EQ(TraceResult.error().Code, ConfigurationErrorCode::UnknownField);
    }

    TEST(PreviewTaskLoggingConfiguration, RejectsInvalidLoggingValues)
    {
        const auto InvalidLevel = ReplaceFirst(
            std::string(ValidJson), "\"Level\": \"Info\"", "\"Level\": \"Verbose\"");
        const auto InvalidDirectory = ReplaceFirst(
            std::string(ValidJson), "\"Directory\": \"logs\"", "\"Directory\": \"\"");
        const auto InvalidFileName = ReplaceFirst(
            std::string(ValidJson), "\"FileName\": \"preview.log\"",
            "\"FileName\": \"nested/preview.log\"");
        const auto InvalidRotateBytes = ReplaceFirst(
            std::string(ValidJson), "\"RotateBytes\": 67108864", "\"RotateBytes\": 0");
        const auto InvalidRotateFiles = ReplaceFirst(
            std::string(ValidJson), "\"RotateFiles\": 8", "\"RotateFiles\": 0");
        const auto InvalidFlushInterval = ReplaceFirst(
            std::string(ValidJson), "\"FlushIntervalMs\": 250", "\"FlushIntervalMs\": 0");

        const auto LevelResult = Parser::ParseJson(InvalidLevel);
        const auto DirectoryResult = Parser::ParseJson(InvalidDirectory);
        const auto FileNameResult = Parser::ParseJson(InvalidFileName);
        const auto RotateBytesResult = Parser::ParseJson(InvalidRotateBytes);
        const auto RotateFilesResult = Parser::ParseJson(InvalidRotateFiles);
        const auto FlushIntervalResult = Parser::ParseJson(InvalidFlushInterval);

        ASSERT_FALSE(LevelResult.has_value());
        EXPECT_EQ(LevelResult.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(LevelResult.error().Path, "Logging.Level");
        ASSERT_FALSE(DirectoryResult.has_value());
        EXPECT_EQ(DirectoryResult.error().Path, "Logging.Directory");
        ASSERT_FALSE(FileNameResult.has_value());
        EXPECT_EQ(FileNameResult.error().Path, "Logging.FileName");
        ASSERT_FALSE(RotateBytesResult.has_value());
        EXPECT_EQ(RotateBytesResult.error().Path, "Logging.RotateBytes");
        ASSERT_FALSE(RotateFilesResult.has_value());
        EXPECT_EQ(RotateFilesResult.error().Path, "Logging.RotateFiles");
        ASSERT_FALSE(FlushIntervalResult.has_value());
        EXPECT_EQ(FlushIntervalResult.error().Path, "Logging.FlushIntervalMs");
    }

    TEST(PreviewTaskLoggingConfiguration, RejectsInvalidLoggingTypes)
    {
        const auto InvalidConsole = ReplaceFirst(
            std::string(ValidJson), "\"Console\": false", "\"Console\": \"false\"");

        const auto Result = Parser::ParseJson(InvalidConsole);

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidType);
    }

    TEST(PreviewTask3Configuration, RejectsDuplicateIds)
    {
        const auto Json = ReplaceFirst(
            std::string(ValidJson),
            "\"Routes\": [],",
            "\"Routes\": [{\"Id\": \"same\", \"Match\": \"*\", \"Target\": \"direct\", \"Requires\": []},"
            "{\"Id\": \"same\", \"Match\": \"example\", \"Target\": \"direct\", \"Requires\": []}],");

        const auto Result = Parser::ParseJson(Json);

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::DuplicateId);
    }

    TEST(PreviewTask3Configuration, RejectsInvalidPortsAndTimeouts)
    {
        const auto BadPort = ReplaceFirst(std::string(ValidJson), "\"Port\": 1080", "\"Port\": 0");
        const auto BadTimeout = ReplaceFirst(
            std::string(ValidJson), "\"Timeout\": 5000", "\"Timeout\": 0");

        const auto PortResult = Parser::ParseJson(BadPort);
        const auto TimeoutResult = Parser::ParseJson(BadTimeout);

        ASSERT_FALSE(PortResult.has_value());
        EXPECT_EQ(PortResult.error().Code, ConfigurationErrorCode::InvalidValue);
        ASSERT_FALSE(TimeoutResult.has_value());
        EXPECT_EQ(TimeoutResult.error().Code, ConfigurationErrorCode::InvalidValue);
    }

    TEST(PreviewTaskDConfiguration, RequiresOneTcpListenerAndOneSharedUdpQuicEntry)
    {
        const auto NoTcp = ReplaceFirst(
            std::string(ValidJson),
            "\"Tcp\": [{\"Id\": \"tcp-main\", \"Address\": \"127.0.0.1\", \"Port\": 1080, \"Timeout\": 5000}]",
            "\"Tcp\": []");
        const auto TwoTcp = ReplaceFirst(
            std::string(ValidJson),
            "\"Tcp\": [{\"Id\": \"tcp-main\", \"Address\": \"127.0.0.1\", \"Port\": 1080, \"Timeout\": 5000}]",
            "\"Tcp\": [{\"Id\": \"tcp-main\", \"Address\": \"127.0.0.1\", \"Port\": 1080, \"Timeout\": 5000}, {\"Id\": \"tcp-second\", \"Address\": \"127.0.0.1\", \"Port\": 1083, \"Timeout\": 5000}]");
        const auto MismatchedQuic = ReplaceFirst(
            std::string(ValidJson), "\"Port\": 1081, \"Timeout\": 5000}],\n    \"Timeout\": 5000",
            "\"Port\": 1082, \"Timeout\": 5000}],\n    \"Timeout\": 5000");

        const auto NoTcpResult = Parser::ParseJson(NoTcp);
        const auto TwoTcpResult = Parser::ParseJson(TwoTcp);
        const auto MismatchedResult = Parser::ParseJson(MismatchedQuic);

        ASSERT_FALSE(NoTcpResult.has_value());
        EXPECT_EQ(NoTcpResult.error().Path, "Listeners.Tcp");
        ASSERT_FALSE(TwoTcpResult.has_value());
        EXPECT_EQ(TwoTcpResult.error().Path, "Listeners.Tcp");
        ASSERT_FALSE(MismatchedResult.has_value());
        EXPECT_EQ(MismatchedResult.error().Path, "Listeners.Quic[0]");
    }

    TEST(PreviewTaskDConfiguration, ValidatesOperationsEndpointAddressAndPort)
    {
        const auto InvalidAddress = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "0.0.0.0:9090");
        const auto InvalidPort = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "127.0.0.1:65536");
        const auto MissingPort = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "127.0.0.1");
        const auto InvalidIpv6 = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "::1:9090");

        const auto AddressResult = Parser::ParseJson(InvalidAddress);
        const auto PortResult = Parser::ParseJson(InvalidPort);
        const auto MissingPortResult = Parser::ParseJson(MissingPort);
        const auto Ipv6Result = Parser::ParseJson(InvalidIpv6);

        for (const auto &Result : {AddressResult, PortResult, MissingPortResult, Ipv6Result})
        {
            ASSERT_FALSE(Result.has_value());
            EXPECT_EQ(Result.error().Path, "Operations.Endpoint");
            EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        }
    }

    TEST(PreviewTask3Generation, RejectsUnresolvedSecretReferences)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back({"missing-account", "missing", ""});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.Generation = Preview::GenerationId{1};
        Options.SecretResolver = [](std::string_view) -> std::optional<std::string> { return std::nullopt; };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
    }

    TEST(PreviewTask3Generation, RejectsUnresolvedSecretReferencesWithoutResolver)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back({"missing-account", "missing", ""});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Result.error().Path, "Accounts[1].SecretRef");
    }

    TEST(PreviewTask3Generation, RejectsEmptyResolvedSecret)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back({"empty-account", "empty", ""});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.SecretResolver = [](std::string_view) -> std::optional<std::string>
        {
            return std::string{};
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Result.error().Path, "Accounts[1].SecretRef");
    }

    TEST(PreviewTask3Generation, RejectsThrowingSecretResolver)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back({"throwing-account", "throwing", ""});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.SecretResolver = [](std::string_view) -> std::optional<std::string>
        {
            throw std::runtime_error("resolver failure");
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Result.error().Path, "Accounts[1].SecretRef");
    }

    TEST(PreviewTask3Generation, AcceptsResolvedSecretReferences)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Accounts.push_back({"resolved-account", "secret/account", ""});
        Options.SecretResolver = [](std::string_view Reference) -> std::optional<std::string>
        {
            return Reference == "secret/account" ? std::optional<std::string>{"resolved-value"}
                                                  : std::nullopt;
        };
        Options.Generation = Preview::GenerationId{1};

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        const auto Secret = (*Result)->LookupSecret("secret/account");
        ASSERT_EQ(Secret.size(), 14U);
        constexpr std::array<unsigned int, 14> ExpectedBytes{
            114U, 101U, 115U, 111U, 108U, 118U, 101U,
            100U, 45U, 118U, 97U, 108U, 117U, 101U};
        for (std::size_t Index = 0; Index < Secret.size(); ++Index)
        {
            EXPECT_EQ(std::to_integer<unsigned int>(Secret[Index]), ExpectedBytes[Index]);
        }
        EXPECT_EQ((*Result)->Configuration().Accounts.back().SecretRef, "secret/account");
    }

    TEST(PreviewTask3Generation, CachesRepeatedCarrierSecretReferences)
    {
        const auto Json = MakeConfigurationJson(
            NativeProtocol,
            std::string(RealityCarrier) + "," + std::string(ShadowTlsCarrier) + "," +
                std::string(RestlsCarrier),
            {});
        const auto Parsed = Parser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        auto Configuration = *Parsed;
        Configuration.Accounts.front().SecretRef = "secret/reality/private-key";
        Configuration.Accounts.front().Credential.clear();

        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeStaticBuiltinSnapshot();
        ASSERT_NE(Options.Builtins, nullptr);

        constexpr std::array<std::pair<std::string_view, std::string_view>, 3> Secrets{
            std::pair{"secret/reality/private-key", "reality-key-material"},
            std::pair{"secret/shadowtls/password", "shadowtls-password"},
            std::pair{"secret/restls/password", "restls-password"}};
        std::size_t ResolverCalls = 0;
        Options.SecretResolver = [&ResolverCalls, &Secrets](std::string_view Reference)
            -> std::optional<std::string>
        {
            ++ResolverCalls;
            for (const auto &[Name, Value] : Secrets)
            {
                if (Name == Reference)
                {
                    return std::string(Value);
                }
            }
            return std::nullopt;
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        EXPECT_EQ(ResolverCalls, 3U);

        const auto &Generated = (*Result)->Configuration();
        EXPECT_EQ(Generated.Accounts.front().SecretRef, "secret/reality/private-key");
        EXPECT_TRUE(Generated.Accounts.front().Credential.empty());
        EXPECT_EQ(std::get<RealityOptions>(Generated.Carriers[0].Options).PrivateKeyRef,
                  "secret/reality/private-key");
        EXPECT_EQ(std::get<ShadowTlsOptions>(Generated.Carriers[1].Options).PasswordSecretRef,
                  "secret/shadowtls/password");
        EXPECT_EQ(std::get<RestlsOptions>(Generated.Carriers[2].Options).PasswordSecretRef,
                  "secret/restls/password");

        const auto AccountSecret = (*Result)->LookupSecret("secret/reality/private-key");
        const auto RealitySecret = (*Result)->LookupSecret("secret/reality/private-key");
        ASSERT_FALSE(AccountSecret.empty());
        EXPECT_EQ(AccountSecret.data(), RealitySecret.data());
        for (const auto &[Name, Value] : Secrets)
        {
            const auto Resolved = (*Result)->LookupSecret(Name);
            ASSERT_EQ(Resolved.size(), Value.size());
            EXPECT_TRUE(std::equal(
                Resolved.begin(), Resolved.end(),
                reinterpret_cast<const std::byte *>(Value.data())));
        }
    }

    TEST(PreviewTask3Generation, RejectsTrustTunnelCarrierBeforeResolvingSecrets)
    {
        auto Configuration = ParseValid();
        CarrierConfiguration Carrier;
        Carrier.Id = "carrier-trusttunnel";
        Carrier.Name = "trusttunnel";
        Carrier.Builtin = "trusttunnel";
        Carrier.Options = TrustTunnelOptions{
            .ServerNames = {"www.amazon.com"},
            .CertificateFile = "cert.pem",
            .PrivateKeySecretRef = "secret/trusttunnel/private-key",
            .PasswordSecretRef = "secret/trusttunnel/password"};
        Configuration.Carriers.push_back(std::move(Carrier));

        GenerationBuildOptions Options;
        Options.Configuration = std::move(Configuration);
        Options.Builtins = MakeDescriptorSnapshot({"carrier", "trusttunnel", CapabilitySet{}, {}});
        ASSERT_NE(Options.Builtins, nullptr);
        std::size_t ResolverCalls = 0;
        Options.SecretResolver = [&ResolverCalls](std::string_view)
            -> std::optional<std::string>
        {
            ++ResolverCalls;
            return std::string{"not-reached"};
        };

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
        EXPECT_EQ(ResolverCalls, 0U);
    }

    TEST(PreviewTask3Generation, RejectsMissingCapabilitiesBeforePublication)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Runtime.RequiredCapabilities = {"Tls"};
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Options.Generation = Preview::GenerationId{1};

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
    }

    TEST(PreviewTask3Generation, RejectsBuiltinCapabilitiesNotProvidedByFrozenDescriptor)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Builtins.push_back(
            {"builtin-core-only", "protocol", "core-only", {}, {"Tls"}});
        Options.Configuration.Runtime.RequiredCapabilities = {"Tls"};

        Registry RegistryValue;
        Preview::Composition::Builtin::BuiltinDescriptor Descriptor;
        Descriptor.Kind = Preview::KindId::From("protocol");
        Descriptor.Name = Preview::NameId::From("core-only");
        Descriptor.Provides = CapabilitySet{Capability::Core};
        Descriptor.Callback = [](const Preview::Composition::Builtin::BuiltinRequest &)
            -> Preview::Foundation::Expected<void> { return {}; };
        ASSERT_TRUE(RegistryValue.Register(std::move(Descriptor)));
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        ASSERT_TRUE(Frozen);
        Options.Builtins = *Frozen;
        Options.Generation = Preview::GenerationId{1};

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "Builtins[0].Provides");
    }

    TEST(PreviewTask3Generation, RejectsUnknownBuiltinReferenceAgainstEmptySnapshot)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Builtins.push_back(
            {"builtin-unknown", "protocol", "unknown", {}, {}});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Builtins[0]");
    }

    TEST(PreviewTask3ProtocolBindingCapability, ParserAllowsProtocolAndCarrierBeforeSnapshotFreeze)
    {
        const auto Json = MakeConfigurationJson(NativeProtocol, NativeCarrier, {});
        const auto Parsed = Parser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        ASSERT_EQ(Parsed->Protocols.size(), 1U);
        ASSERT_EQ(Parsed->Carriers.size(), 1U);
        EXPECT_EQ(Parsed->Protocols.front().Builtin, "socks5");
        EXPECT_EQ(Parsed->Carriers.front().Builtin, "native");
    }

    TEST(PreviewTask3ProtocolBindingCapability, GenerationRequiresSnapshotForConfiguredProtocol)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(MakeProtocolConfiguration("http"));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

    TEST(PreviewTask3ProtocolBindingCapability, GenerationRequiresSnapshotForConfiguredCarrier)
    {
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Carriers.push_back(MakeNativeCarrierConfiguration("native"));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

    TEST(PreviewTask3ProtocolBindingCapability, RejectsUnknownProtocolBuiltin)
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

    TEST(PreviewTask3ProtocolBindingCapability, RejectsUnknownCarrierBuiltin)
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

    TEST(PreviewTask3ProtocolBindingCapability, RejectsDisabledProtocolBuiltin)
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

    TEST(PreviewTask3ProtocolBindingCapability, RejectsHttpUdpBindingWithoutDescriptorDatagram)
    {
        auto Protocol = MakeProtocolConfiguration("http");
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(Protocol);
        ProtocolBindingConfiguration Binding;
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

    TEST(PreviewTask3ProtocolBindingCapability, RejectsHttpMuxWithoutDescriptorMultiplex)
    {
        auto Protocol = MakeProtocolConfiguration("http");
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(Protocol);
        ProtocolBindingConfiguration Binding;
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

    TEST(PreviewTask3ProtocolBindingCapability, AcceptsShadowsocks2022AliasForSs2022Descriptor)
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

    TEST(PreviewTask3ProtocolBindingCapability, AcceptsSocks5UdpFromItsDescriptor)
    {
        auto Protocol = MakeProtocolConfiguration("socks5");
        GenerationBuildOptions Options;
        Options.Configuration = ParseValid();
        Options.Configuration.Protocols.push_back(Protocol);
        ProtocolBindingConfiguration Binding;
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

    TEST(PreviewTask3ProtocolBindingCapability, PreservesTrustedCapabilitiesAndPinsSnapshot)
    {
        Registry RegistryValue({.InitialCapabilities = CapabilitySet{Capability::Core}});
        Preview::Composition::Builtin::BuiltinDescriptor Descriptor;
        Descriptor.Kind = Preview::KindId::From("protocol");
        Descriptor.Name = Preview::NameId::From("trusted");
        Descriptor.Provides = CapabilitySet{Capability::Multiplex};
        Descriptor.Requires = CapabilitySet{Capability::Core};
        bool CallbackInvoked = false;
        Descriptor.Callback = [&CallbackInvoked](
                                 const Preview::Composition::Builtin::BuiltinRequest &)
            -> Preview::Foundation::Expected<void>
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

    TEST(PreviewTask3ProtocolBindingCapability, PreservesWebsocketAliasForWsDescriptor)
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

    TEST(PreviewTask3Generation, RequiresFrozenSnapshotForConfiguredBuiltins)
    {
        const auto Json = ReplaceFirst(
            std::string(ValidJson), "\"Builtins\": [],",
            "\"Builtins\": [{\"Id\":\"builtin-no-snapshot\",\"Kind\":\"protocol\","
            "\"Name\":\"core-only\",\"Requires\":[],\"Provides\":[]}],");
        const auto Parsed = Parser::ParseJson(Json);
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Builtins[0]");
    }

    TEST(PreviewTask3Generation, PinsImmutableGenerationsAcrossSuccessfulReload)
    {
        GenerationBuildOptions InitialOptions;
        InitialOptions.Configuration = ParseValid();
        InitialOptions.Builtins = MakeBuiltinSnapshot(CapabilitySet{Capability::Core});
        InitialOptions.Generation = Preview::GenerationId{1};
        const auto Initial = GenerationBuilder::Build(std::move(InitialOptions));
        ASSERT_TRUE(Initial.has_value()) << Initial.error().Message;

        ConfigurationStore Store(*Initial);
        const auto Pinned = Store.Pin();
        ASSERT_NE(Pinned, nullptr);

        ReloadRequest Request;
        Request.Configuration = ParseValid();
        Request.Configuration.Runtime.WorkerCount = 3;
        Request.Builtins = MakeBuiltinSnapshot(CapabilitySet{Capability::Core});
        bool PublishedBeforeAcknowledgement = false;
        Request.Workers.push_back([](const ConfigurationGeneration &Generation) {
            return Generation.Id() == Preview::GenerationId{2};
        });
        Request.Workers.push_back([&Store, &PublishedBeforeAcknowledgement](const ConfigurationGeneration &)
        {
            PublishedBeforeAcknowledgement = Store.Current()->Id() != Preview::GenerationId{1};
            return true;
        });

        ReloadCoordinator Coordinator(Store);
        const auto Reloaded = Coordinator.Reload(std::move(Request));

        ASSERT_TRUE(Reloaded.has_value()) << Reloaded.error().Message;
        EXPECT_EQ(Pinned->Id(), Preview::GenerationId{1});
        EXPECT_EQ(Pinned->Configuration().Runtime.WorkerCount, 2U);
        EXPECT_EQ(Store.Current()->Id(), Preview::GenerationId{2});
        EXPECT_EQ(Store.Current()->Configuration().Runtime.WorkerCount, 3U);
        EXPECT_FALSE(PublishedBeforeAcknowledgement);
    }

    TEST(PreviewTask3Generation, ReloadFailurePreservesTheOldGeneration)
    {
        GenerationBuildOptions InitialOptions;
        InitialOptions.Configuration = ParseValid();
        InitialOptions.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        InitialOptions.Generation = Preview::GenerationId{7};
        const auto Initial = GenerationBuilder::Build(std::move(InitialOptions));
        ASSERT_TRUE(Initial.has_value()) << Initial.error().Message;

        ConfigurationStore Store(*Initial);
        ReloadRequest Request;
        Request.Configuration = ParseValid();
        Request.Configuration.Runtime.WorkerCount = 4;
        Request.Builtins = MakeBuiltinSnapshot(CapabilitySet{});
        Request.Workers.push_back([](const ConfigurationGeneration &) { return false; });

        ReloadCoordinator Coordinator(Store);
        const auto Reloaded = Coordinator.Reload(std::move(Request));

        ASSERT_FALSE(Reloaded.has_value());
        EXPECT_EQ(Reloaded.error().Code, ConfigurationErrorCode::WorkerRejected);
        ASSERT_NE(Store.Current(), nullptr);
        EXPECT_EQ(Store.Current()->Id(), Preview::GenerationId{7});
        EXPECT_EQ(Store.Current()->Configuration().Runtime.WorkerCount, 2U);
    }

    TEST(PreviewTask3Generation, RejectsUnknownProtocolBuiltinAgainstFrozenSnapshot)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"unknown-protocol"});
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

    TEST(PreviewTask3Generation, RejectsDisabledProtocolBuiltin)
    {
        auto RegistryValue = Preview::Composition::Builtin::MakeStaticBuiltinRegistry();
        Preview::Composition::Builtin::StaticBuiltinOptions BuiltinOptions;
        BuiltinOptions.Disabled.push_back({"protocol", "socks5"});
        const auto Registration = Preview::Composition::Builtin::RegisterProtocolBuiltins(
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

    TEST(PreviewTask3Generation, RejectsProtocolBuiltinRegisteredUnderCarrierKind)
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

    TEST(PreviewTask3Generation, RequiresFrozenSnapshotForConfiguredProtocol)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5"});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Protocols[0].Builtin");
    }

    TEST(PreviewTask3Generation, RejectsUnknownCarrierBuiltinAgainstFrozenSnapshot)
    {
        const auto Parsed = Parser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;
        Options.Builtins = MakeBuiltinSnapshot(CapabilitySet{});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

    TEST(PreviewTask3Generation, RejectsCarrierBuiltinRegisteredUnderProtocolKind)
    {
        const auto Parsed = Parser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
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

    TEST(PreviewTask3Generation, RequiresFrozenSnapshotForConfiguredCarrier)
    {
        const auto Parsed = Parser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingReference);
        EXPECT_EQ(Result.error().Path, "Carriers[0].Builtin");
    }

    TEST(PreviewTask3Generation, RejectsTcpBindingWithoutDescriptorStream)
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

    TEST(PreviewTask3Generation, RejectsUdpBindingWithoutDescriptorDatagramOrQuic)
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

    TEST(PreviewTask3Generation, RejectsMuxBindingWithoutDescriptorMultiplex)
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

    TEST(PreviewTask3Generation, RejectsUnimplementedPhysicalMuxProfiles)
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

    TEST(PreviewTask3Generation, AcceptsH2MuxWhenProtocolProvidesMultiplex)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"socks5", true, false, {"H2Mux"}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "socks5",
            CapabilitySet{Capability::Stream, Capability::Datagram, Capability::Multiplex}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
    }

    TEST(PreviewTask3Generation, AcceptsQuicProtocolDescriptorForUdpBinding)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"hysteria2", false, true, {}});
        Options.Configuration.Protocols.back().Quic =
            ProtocolConfiguration::QuicOptions{
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

    TEST(PreviewTask3Generation, RejectsTcpForQuicOnlyDescriptor)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"hysteria2", true, false, {}});
        Options.Configuration.Protocols.back().Quic =
            ProtocolConfiguration::QuicOptions{
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
        const auto *Descriptor = Options.Builtins->Find(Preview::BuiltinId{1});
        ASSERT_NE(Descriptor, nullptr);
        EXPECT_TRUE(Descriptor->Descriptor.Provides.Contains(Capability::Stream));

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingCapability);
        EXPECT_EQ(Result.error().Path, "ProtocolBindings[0].TcpEnabled");
    }

    TEST(PreviewTask3Generation, ResolvesShadowsocks2022AliasToSs2022)
    {
        GenerationBuildOptions Options;
        Options.Configuration = MakeBoundProtocolConfiguration({"shadowsocks2022", false, true, {}});
        Options.Builtins = MakeDescriptorSnapshot({
            "protocol", "ss2022", CapabilitySet{Capability::Stream, Capability::Datagram}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        ASSERT_EQ((*Result)->Configuration().Protocols.size(), 1U);
        EXPECT_EQ((*Result)->Configuration().Protocols.front().Builtin, "shadowsocks2022");
        const auto *Descriptor = (*Result)->Builtins()->Find(Preview::BuiltinId{1});
        ASSERT_NE(Descriptor, nullptr);
        EXPECT_EQ(Descriptor->Descriptor.Name.Value(), "ss2022");
    }

    TEST(PreviewTask3Generation, ResolvesCarrierFromFrozenSnapshot)
    {
        const auto Parsed = Parser::ParseJson(MakeConfigurationJson({}, NativeCarrier, {}));
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions Options;
        Options.Configuration = *Parsed;
        Options.Builtins = MakeDescriptorSnapshot({
            "carrier", "native", CapabilitySet{Capability::Tls, Capability::Stream}, {}});

        const auto Result = GenerationBuilder::Build(std::move(Options));

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        ASSERT_EQ((*Result)->Builtins()->Size(), 1U);
    }

    TEST(PreviewTask3Generation, PreservesDescriptorCapabilitiesAndPinsFrozenSnapshot)
    {
        auto Snapshot = MakeDescriptorSnapshot({
            "protocol", "capability-source", CapabilitySet{Capability::Datagram}, {}});
        ASSERT_NE(Snapshot, nullptr);
        std::weak_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> SnapshotPin = Snapshot;

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

    TEST(PreviewQuicConfiguration, BuildsHysteriaCredentialContextPerGeneration)
    {
        auto Configuration = ParseValid();
        Configuration.Protocols.clear();
        Configuration.Protocols.push_back(ProtocolConfiguration{
            "protocol-hysteria2",
            "hysteria2",
            "hysteria2",
            {},
            ProtocolConfiguration::QuicOptions{
                "h3", "quic.example", "secret/hysteria/password", 32, 64}});
        Configuration.ProtocolBindings.clear();
        ProtocolBindingConfiguration Binding;
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

    TEST(PreviewQuicConfiguration, RejectsMissingOrWrongHysteriaCredentialAndAlpn)
    {
        auto Configuration = ParseValid();
        Configuration.Protocols.clear();
        Configuration.Protocols.push_back(ProtocolConfiguration{
            "protocol-hysteria2", "hysteria2", "hysteria2", {},
            ProtocolConfiguration::QuicOptions{
                "h2", "quic.example", "secret/hysteria/password", 32, 64}});
        Configuration.ProtocolBindings.clear();
        ProtocolBindingConfiguration Binding;
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

} // namespace
