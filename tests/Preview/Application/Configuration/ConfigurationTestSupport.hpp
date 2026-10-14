/**
 * @file ConfigurationTestSupport.hpp
 * @brief ConfigurationTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

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
#include <Preview/Application/Assembly/ConfigurationAssembly.hpp>
#include <Preview/Composition/Builtin/Registry.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>
#include <Preview/Runtime/Worker.hpp>

namespace
{

    using Preview::Application::Configuration::BuiltinConfiguration;
    using Preview::Contract::CarrierConfiguration;
    using Preview::Application::Configuration::ConfigurationErrorCode;
    using Preview::Application::Configuration::ConfigurationGeneration;
    using Preview::Application::Configuration::GenerationBuildOptions;
    using Preview::Application::Configuration::GenerationBuilder;
    using Preview::Contract::NativeTlsOptions;
    using Preview::Contract::ProtocolConfiguration;
    using Preview::Contract::ProtocolBindingConfiguration;
    using Preview::Application::Configuration::PreviewConfiguration;
    using Preview::Contract::RealityOptions;
    using Preview::Contract::RestlsOptions;
    using Preview::Contract::ShadowTlsOptions;
    using Preview::Application::Configuration::Parser;
    using Preview::Application::Configuration::ReloadCoordinator;
    using Preview::Application::Configuration::ReloadRequest;
    using Preview::Runtime::GenerationPrepareAck;
    using Preview::Runtime::GenerationPrepareStatus;
    using Preview::Runtime::GenerationPublication;
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

    auto MakeProtocolConfiguration(std::string Builtin) -> Preview::Contract::ProtocolConfiguration
    {
        Preview::Contract::ProtocolConfiguration Protocol;
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
        Configuration.Protocols.push_back(Preview::Contract::ProtocolConfiguration{
            "protocol-test", std::string(Fixture.Builtin), std::string(Fixture.Builtin), {}});

        Preview::Contract::ProtocolBindingConfiguration Binding;
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
    "Type": "NativeTls",
    "CertificateFile": "cert.pem",
    "PrivateKeyFile": "key.pem"
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

























































































} // namespace


