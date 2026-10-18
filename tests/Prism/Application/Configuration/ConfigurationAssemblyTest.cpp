/**
 * @file ConfigurationAssemblyTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfigurationTestSupport.hpp"
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Protocols/Vless/Binding.hpp>

namespace
{
    /**
     * @brief 构造 typed facade carrier 的完整配置片段。
     * @return 保持生产 schema 字段名和六种 carrier options 的 JSON 片段。
     */
    auto MakeTypedFacadeCarrierJson() -> std::string_view
    {
        return R"json(
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
    }

    /**
     * @brief 解析 typed carrier 并核对每个 options variant 与业务字段。
     * @details 保留六个 carrier 的类型、secret ref、handshake、路径和 mode 合同。
     */
    auto RunTypedFacadeCarrierAssertions() -> void
    {
        const auto Json = MakeConfigurationJson(
            NativeProtocol, MakeTypedFacadeCarrierJson(), {});
        const auto Parsed = Parser::Parse(
            {.Json = Json, .Options = {.CheckSecrets = false}});

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        ASSERT_EQ(Parsed->Carriers.size(), 6U);
        EXPECT_TRUE(std::holds_alternative<Prism::Contract::RealityOptions>(
            Parsed->Carriers[0].Options));
        EXPECT_TRUE(std::holds_alternative<Prism::Contract::ShadowTlsOptions>(
            Parsed->Carriers[1].Options));
        EXPECT_TRUE(std::holds_alternative<Prism::Contract::RestlsOptions>(
            Parsed->Carriers[2].Options));
        EXPECT_TRUE(std::holds_alternative<Prism::Contract::WebSocketOptions>(
            Parsed->Carriers[3].Options));
        EXPECT_TRUE(std::holds_alternative<Prism::Contract::XhttpOptions>(
            Parsed->Carriers[4].Options));
        EXPECT_TRUE(std::holds_alternative<Prism::Contract::GunOptions>(
            Parsed->Carriers[5].Options));
        EXPECT_EQ(std::get<Prism::Contract::RealityOptions>(
                      Parsed->Carriers[0].Options).HandshakeTarget,
                  "www.microsoft.com:443");
        EXPECT_EQ(std::get<Prism::Contract::RealityOptions>(
                      Parsed->Carriers[0].Options).PrivateKeyRef,
                  "secret/reality/private-key");
        EXPECT_EQ(std::get<Prism::Contract::ShadowTlsOptions>(
                      Parsed->Carriers[1].Options).PasswordSecretRef,
                  "secret/shadowtls/password");
        const auto &Gun = std::get<Prism::Contract::GunOptions>(
            Parsed->Carriers[5].Options);
        EXPECT_EQ(Gun.Path, "/GunService/Tun");
        EXPECT_EQ(Gun.ServiceName, "GunService");
        EXPECT_EQ(Gun.Mode, "Grpc");
        const auto &Xhttp = std::get<Prism::Contract::XhttpOptions>(
            Parsed->Carriers[4].Options);
        EXPECT_EQ(Xhttp.Path, "/xhttp");
        EXPECT_EQ(Xhttp.Host, "www.example.com");
        EXPECT_EQ(Xhttp.Mode, "StreamOne");
    }
} // namespace

TEST(PrismConfigurationAssembly, KeepsPureConfigurationHelpersSelfContained)
    {
        EXPECT_EQ(Prism::Network::ParsePort("1").value_or(0),
                  1);
        EXPECT_FALSE(Prism::Network::ParsePort("0").has_value());
        EXPECT_FALSE(Prism::Network::ParsePort("65536").has_value());

        const auto Socks=Prism::Composition::Protocol::ProtocolCatalog::Find("socks5");
        ASSERT_TRUE(Socks.has_value());
        EXPECT_EQ(Socks->Id,Prism::Contract::ProtocolType::Socks5);
        EXPECT_TRUE(Prism::Composition::Protocol::ProtocolCatalog::Supports(
            "tuic", Prism::Composition::Recognition::OperationScope::QuicBinding));
        EXPECT_FALSE(Prism::Composition::Protocol::ProtocolCatalog::Supports(
            "socks5", Prism::Composition::Recognition::OperationScope::QuicBinding));

        Prism::Contract::ProtocolConfiguration Protocol{"socks","socks5","socks5",{}, {}};
        Prism::Contract::ProtocolBindingConfiguration Binding;
        Binding.Id="binding";
        Binding.ProtocolId=Protocol.Id;
        Binding.MuxModes = {"Smux", "H2Mux"};
        ASSERT_EQ(Prism::Composition::Provider::ConfiguredMuxMode(Protocol, Binding),
                  Prism::Mux::Mode::H2Mux);

        const auto Uuid = Prism::Vless::ParseAccountUuid(
            "00112233-4455-6677-8899-aabbccddeeff");
        ASSERT_TRUE(Uuid.has_value());
        EXPECT_EQ((*Uuid)[0], 0x00U);
        EXPECT_EQ((*Uuid)[15], 0xffU);

        Prism::Application::Configuration::DnsConfiguration Dns;
        Dns.Timeout = 321;
        Dns.Servers = {"tls://1.1.1.1"};
        const auto DnsConfig = Prism::Application::Assembly::MakeDnsConfig(Dns);
        EXPECT_EQ(DnsConfig.TimeoutMs, 321U);
        EXPECT_TRUE(DnsConfig.DisableIpv6);
        ASSERT_EQ(DnsConfig.Servers.size(), 1U);
        EXPECT_EQ(DnsConfig.Servers.front().Address, "1.1.1.1");
        EXPECT_EQ(DnsConfig.Servers.front().Port, 853U);
    }

TEST(PrismTask4Configuration, ParsesTypedCarrierMatchAndNativeTlsOptions)
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
        ASSERT_TRUE(std::holds_alternative<Prism::Contract::NativeTlsOptions>(Carrier.Options));
        const auto &Options = std::get<Prism::Contract::NativeTlsOptions>(Carrier.Options);
        EXPECT_EQ(Options.CertificateFile, "cert.pem");
        EXPECT_EQ(Options.PrivateKeyFile, "key.pem");
    }

TEST(PrismTask4Configuration, ParsesTypedFacadeCarrierOptions)
{
    RunTypedFacadeCarrierAssertions();
}

TEST(PrismTask4Configuration, AcceptsXhttpModes)
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
            std::get<Prism::Contract::XhttpOptions>(
                Configuration.Carriers[0].Options)
                .Mode = Mode;
            const auto Result = Parser::Validate(
                Prism::Application::Configuration::ValidationRequest{
                    Configuration,
                    Prism::Application::Configuration::ValidationOptions{
                        .CheckSecrets = false, .CheckCapabilities = false}});
            EXPECT_TRUE(Result.has_value()) << Mode;
        }

        auto InvalidConfiguration = *Parsed;
        std::get<Prism::Contract::XhttpOptions>(
            InvalidConfiguration.Carriers[0].Options)
            .Mode = "Unknown";
        const auto InvalidResult = Parser::Validate(
            Prism::Application::Configuration::ValidationRequest{
                InvalidConfiguration,
                Prism::Application::Configuration::ValidationOptions{
                    .CheckSecrets = false, .CheckCapabilities = false}});
        ASSERT_FALSE(InvalidResult.has_value());
        EXPECT_EQ(InvalidResult.error().Path, "Carriers[0].Options.Mode");
        EXPECT_EQ(InvalidResult.error().Code, ConfigurationErrorCode::InvalidValue);
    }

TEST(PrismTask4Configuration, RejectsLegacyRealityFieldNames)
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

TEST(PrismTask4Configuration, ParsesProtocolBindingAndRecognitionRoute)
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
        EXPECT_TRUE(Binding.Recognition.Fallback);
    }

TEST(PrismTask4Configuration, ParsesTopLevelRecognitionMode)
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

TEST(PrismTask4Configuration, RejectsRetiredDeterministicRouteSpelling)
    {
        const auto Json = ReplaceFirst(std::string(ValidJson), "  \"ProtocolBindings\": [],",
            "  \"ProtocolBindings\": [],\n  \"Recognition\": {\"Mode\": \"DeterministicRoute\"},");
        const auto Parsed = Parser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
        ASSERT_FALSE(Parsed);
        EXPECT_EQ(Parsed.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Parsed.error().Path, "Recognition.Mode");
    }

TEST(PrismTask4Configuration, AcceptsCanonicalDeterministicSpelling)
    {
        const auto Json = ReplaceFirst(std::string(ValidJson), "  \"ProtocolBindings\": [],",
            "  \"ProtocolBindings\": [],\n  \"Recognition\": {\"Mode\": \"Deterministic\"},");
        const auto Parsed = Parser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed) << Parsed.error().Message;
        EXPECT_EQ(Parsed->Recognition.Mode, "Deterministic");
    }

TEST(PrismTask4Configuration, AllowsAnyTlsAsAProtocolWithoutAnyTlsCarrier)
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

TEST(PrismTask4Configuration, RejectsTypedBindingContractViolations)
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
