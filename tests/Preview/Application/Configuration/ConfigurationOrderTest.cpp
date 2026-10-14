/**
 * @file ConfigurationOrderTest.cpp
 * @brief Preview 配置多错误首错顺序合同测试。
 */

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Application/Configuration/Configuration.hpp>
#include <Preview/Application/Configuration/Validation/ConfigurationValidation.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Preview/Composition/Builtin/Registry.hpp>

namespace
{

    using Preview::Application::Configuration::ConfigurationErrorCode;
    using Preview::Application::Configuration::Parser;
    using Preview::Application::Configuration::PreviewConfiguration;
    using Preview::Contract::ProtocolBindingConfiguration;
    using Preview::Application::Configuration::ValidationOptions;
    using Preview::Application::Configuration::ValidationRequest;

    constexpr std::string_view ValidJson = R"json(
{
  "SchemaVersion": 1,
  "Runtime": {"WorkerCount": 2, "RequiredCapabilities": [], "SessionTimeout": 30000},
  "Listeners": {
    "Tcp": [{"Id": "tcp-main", "Address": "127.0.0.1", "Port": 1080, "Timeout": 5000}],
    "Udp": [],
    "Quic": [],
    "Timeout": 5000
  },
  "Builtins": [],
  "Protocols": [],
  "Carriers": [],
  "ProtocolBindings": [],
  "Accounts": [{"Id": "local", "SecretRef": "", "Credential": "local-token"}],
  "Routes": [],
  "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
  "Statistics": {"Enabled": true, "Interval": 1000},
  "Operations": {"Enabled": true, "Endpoint": "127.0.0.1:9090", "Timeout": 1000},
  "HotReload": {"Enabled": true, "AckTimeout": 5000},
  "Shutdown": {"Timeout": 5000}
}
)json";

    auto ReplaceFirst(std::string Value, const std::string_view From,
                      const std::string_view To) -> std::string
    {
        const auto Position = Value.find(From);
        if (Position != std::string::npos)
        {
            Value.replace(Position, From.size(), To);
        }
        return Value;
    }

    auto MakeStaticBuiltinSnapshot()
        -> std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot>
    {
        auto RegistryValue = Preview::Composition::Builtin::MakeStaticBuiltinRegistry();
        if (!Preview::Composition::Builtin::RegisterStaticBuiltins(RegistryValue, {}))
        {
            return nullptr;
        }
        const auto Frozen = RegistryValue.Freeze(
            Preview::Composition::Builtin::FreezeRequest{});
        return Frozen ? *Frozen : nullptr;
    }

    auto MakeConfigurationJson(const std::string_view Protocols,
                               const std::string_view Carriers,
                               const std::string_view Bindings) -> std::string
    {
        auto Json = ReplaceFirst(
            std::string(ValidJson), "\"Protocols\": [],",
            "\"Protocols\": [" + std::string(Protocols) + "],");
        Json = ReplaceFirst(
            std::move(Json), "\"Carriers\": [],\n  \"ProtocolBindings\": [],",
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

    struct ExpectedConfigurationError final
    {
        ConfigurationErrorCode Code;
        std::string_view Path;
    };

    template <typename Result>
    auto ExpectConfigurationError(
        const Result &Value,
        const ExpectedConfigurationError Expected) -> void
    {
        ASSERT_FALSE(Value.has_value());
        if (Value.has_value())
        {
            return;
        }
        EXPECT_EQ(Value.error().Code, Expected.Code);
        EXPECT_EQ(Value.error().Path, Expected.Path);
    }

    auto ParseWithoutSecrets(const std::string_view Json) -> Parser::Result
    {
        // 公开 v1 解析使用无快照选项，仅关闭 SecretRef 解析。
        return Parser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
    }

    auto MakeStaticValidationOptions() -> ValidationOptions
    {
        // 冻结校验解析配置名称并检查 descriptor 能力声明。
        ValidationOptions Options;
        Options.Builtins = MakeStaticBuiltinSnapshot();
        Options.CheckSecrets = false;
        Options.CheckCapabilities = true;
        Options.RequireBuiltinSnapshot = true;
        return Options;
    }

    auto ParseWithStaticSnapshot(const std::string_view Json) -> Parser::Result
    {
        return Parser::Parse({.Json = Json, .Options = MakeStaticValidationOptions()});
    }

    auto ValidateWithStaticSnapshot(const PreviewConfiguration &Configuration)
        -> Parser::ValidationResult
    {
        return Parser::Validate(
            ValidationRequest{Configuration, MakeStaticValidationOptions()});
    }

    auto MakeFullConfigurationJson() -> std::string
    {
        return ReplaceFirst(
            MakeConfigurationJson(NativeProtocol, NativeCarrier, NativeBinding),
            "\"Builtins\": [],",
            "\"Builtins\": [{\"Id\": \"builtin-socks5\", \"Kind\": \"protocol\", "
            "\"Name\": \"socks5\", \"Requires\": [], \"Provides\": []}],");
    }

    auto MakeFullConfiguration() -> Parser::Result
    {
        return ParseWithoutSecrets(MakeFullConfigurationJson());
    }

    auto MakeHttpConfigurationJson() -> std::string
    {
        auto HttpProtocol = ReplaceFirst(
            std::string(NativeProtocol), "\"Id\": \"protocol-socks5\"",
            "\"Id\": \"protocol-http\"");
        HttpProtocol = ReplaceFirst(
            std::move(HttpProtocol), "\"Name\": \"socks5\"", "\"Name\": \"http\"");
        HttpProtocol = ReplaceFirst(
            std::move(HttpProtocol), "\"Builtin\": \"socks5\"", "\"Builtin\": \"http\"");

        auto HttpBinding = ReplaceFirst(
            std::string(NativeBinding), "\"ProtocolId\": \"protocol-socks5\"",
            "\"ProtocolId\": \"protocol-http\"");
        HttpBinding = ReplaceFirst(
            std::move(HttpBinding), "\"UdpEnabled\": true", "\"UdpEnabled\": false");
        HttpBinding = ReplaceFirst(
            std::move(HttpBinding), "\"MuxModes\": [\"Smux\", \"Yamux\"]",
            "\"MuxModes\": []");
        return MakeConfigurationJson(HttpProtocol, NativeCarrier, HttpBinding);
    }

    auto MakeCarrierAmbiguityJson() -> std::string
    {
        auto SecondaryCarrier = ReplaceFirst(
            std::string(NativeCarrier), "\"Id\": \"carrier-native\"",
            "\"Id\": \"carrier-secondary\"");
        auto PrimaryBinding = ReplaceFirst(
            std::string(NativeBinding), "\"Priority\": 9", "\"Priority\": 0");
        auto SecondaryBinding = ReplaceFirst(
            std::string(NativeBinding), "\"Id\": \"binding-socks5\"",
            "\"Id\": \"binding-secondary\"");
        SecondaryBinding = ReplaceFirst(
            std::move(SecondaryBinding), "carrier-native", "carrier-secondary");
        SecondaryBinding = ReplaceFirst(
            std::move(SecondaryBinding), "\"Priority\": 9", "\"Priority\": 0");
        SecondaryBinding = ReplaceFirst(
            std::move(SecondaryBinding), "\"Pattern\": \"example.com\"",
            "\"Pattern\": \"other.example.com\"");
        return MakeConfigurationJson(
            NativeProtocol,
            std::string(NativeCarrier) + "," + SecondaryCarrier,
            PrimaryBinding + "," + SecondaryBinding);
    }

    TEST(PreviewTaskC11aConfigurationOrder, KeepsListenerErrorsAheadOfLaterSections)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"Port\": 1080", "\"Port\": 0");
        Json = ReplaceFirst(
            std::move(Json), "\"ProtocolId\": \"protocol-socks5\"",
            "\"ProtocolId\": \"missing-protocol\"");
        Json = ReplaceFirst(
            std::move(Json), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::InvalidValue, "Listeners.Tcp[0].Port"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.Listeners.Tcp.front().Port = 0;
        Configuration.ProtocolBindings.front().ProtocolId = "missing-protocol";
        Configuration.Accounts.front().Credential.clear();
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::InvalidValue, "Listeners.Tcp[0].Port"});
    }

    TEST(PreviewTaskC11aConfigurationOrder, KeepsBuiltinErrorsAheadOfProtocols)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"Provides\": []", "\"Provides\": [\"Unknown\"]");
        Json = ReplaceFirst(
            std::move(Json), "\"Name\": \"socks5\",\n  \"Builtin\": \"socks5\"",
            "\"Name\": \"\",\n  \"Builtin\": \"socks5\"");
        Json = ReplaceFirst(
            std::move(Json), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::InvalidValue, "Builtins[0].Provides[0]"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.Builtins.front().Provides = {"Unknown"};
        Configuration.Protocols.front().Name.clear();
        Configuration.Accounts.front().Credential.clear();
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::InvalidValue, "Builtins[0].Provides[0]"});
    }

    TEST(PreviewTaskC11aConfigurationOrder, KeepsProtocolErrorsAheadOfCarriers)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"Builtin\": \"socks5\"",
            "\"Builtin\": \"native\"");
        Json = ReplaceFirst(
            std::move(Json), "\"ServerNames\": [\"example.com\"]",
            "\"ServerNames\": [\"bad..example.com\"]");
        Json = ReplaceFirst(
            std::move(Json), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::InvalidValue, "Protocols[0].Builtin"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.Protocols.front().Builtin = "native";
        Configuration.Carriers.front().Match.ServerNames = {"bad..example.com"};
        Configuration.Accounts.front().Credential.clear();
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::InvalidValue, "Protocols[0].Builtin"});
    }

    TEST(PreviewTaskC11aConfigurationOrder, KeepsCarrierErrorsAheadOfBindings)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"ServerNames\": [\"example.com\"]",
            "\"ServerNames\": [\"bad..example.com\"]");
        Json = ReplaceFirst(
            std::move(Json), "\"ProtocolId\": \"protocol-socks5\"",
            "\"ProtocolId\": \"missing-protocol\"");
        Json = ReplaceFirst(
            std::move(Json), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::InvalidValue, "Carriers[0].Match.ServerNames[0]"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.Carriers.front().Match.ServerNames = {"bad..example.com"};
        Configuration.ProtocolBindings.front().ProtocolId = "missing-protocol";
        Configuration.Accounts.front().Credential.clear();
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::InvalidValue, "Carriers[0].Match.ServerNames[0]"});
    }

    TEST(PreviewTaskC11aConfigurationOrder, KeepsBindingReferencesAheadOfAccounts)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"ProtocolId\": \"protocol-socks5\"",
            "\"ProtocolId\": \"missing-protocol\"");
        Json = ReplaceFirst(
            std::move(Json), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::MissingReference, "ProtocolBindings[0].ProtocolId"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.ProtocolBindings.front().ProtocolId = "missing-protocol";
        Configuration.Accounts.front().Credential.clear();
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::MissingReference, "ProtocolBindings[0].ProtocolId"});

        auto OwnerOptions = MakeStaticValidationOptions();
        Preview::Application::Configuration::Validation::ReferenceValidationOwner Owner(
            Configuration, OwnerOptions);
        ExpectConfigurationError(
            Owner.Validate(),
            {ConfigurationErrorCode::MissingReference, "ProtocolBindings[0].ProtocolId"});
    }

    TEST(PreviewTaskC11aConfigurationOrder, KeepsAccountErrorsAheadOfRoutes)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");
        Json = ReplaceFirst(
            std::move(Json), "  \"Routes\": [],",
            "  \"Routes\": [{\"Id\":\"route-empty\",\"Match\":\"\",\"Target\":\"\"}],");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::InvalidValue, "Accounts[0]"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.Accounts.front().Credential.clear();
        Configuration.Routes.push_back({"route-empty", "", ""});
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::InvalidValue, "Accounts[0]"});
    }

    TEST(PreviewTaskC11aBindingOrder, KeepsProtocolReferencesAheadOfNestedRules)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"ProtocolId\": \"protocol-socks5\"",
            "\"ProtocolId\": \"missing-protocol\"");
        Json = ReplaceFirst(
            std::move(Json), "\"Pattern\": \"example.com\"",
            "\"Pattern\": \"bad..example.com\"");
        Json = ReplaceFirst(
            std::move(Json), "\"MuxModes\": [\"Smux\", \"Yamux\"]",
            "\"MuxModes\": [\"Unknown\"]");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::MissingReference, "ProtocolBindings[0].ProtocolId"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        auto &Binding = Configuration.ProtocolBindings.front();
        Binding.ProtocolId = "missing-protocol";
        Binding.Recognition.Pattern = "bad..example.com";
        Binding.MuxModes = {"Unknown"};
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::MissingReference, "ProtocolBindings[0].ProtocolId"});
    }

    TEST(PreviewTaskC11aBindingOrder, KeepsCarrierCompatibilityAheadOfNestedRules)
    {
        auto Binding = ReplaceFirst(
            std::string(NativeBinding), "protocol-socks5", "protocol-anytls");
        Binding = ReplaceFirst(std::move(Binding), "carrier-native", "carrier-reality");
        Binding = ReplaceFirst(
            std::move(Binding), "\"Pattern\": \"example.com\"",
            "\"Pattern\": \"bad..example.com\"");
        Binding = ReplaceFirst(
            std::move(Binding), "\"MuxModes\": [\"Smux\", \"Yamux\"]",
            "\"MuxModes\": [\"Unknown\"]");
        const auto Json = MakeConfigurationJson(AnyTlsProtocol, RealityCarrier, Binding);

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::InvalidValue, "ProtocolBindings[0].CarrierId"});

        const auto Base = ParseWithoutSecrets(
            MakeConfigurationJson(AnyTlsProtocol, RealityCarrier, {}));
        ASSERT_TRUE(Base.has_value());
        if (!Base)
        {
            return;
        }
        auto Configuration = *Base;
        Preview::Contract::ProtocolBindingConfiguration InvalidBinding;
        InvalidBinding.Id = "binding-anytls";
        InvalidBinding.ProtocolId = "protocol-anytls";
        InvalidBinding.CarrierId = "carrier-reality";
        InvalidBinding.MuxModes = {"Unknown"};
        InvalidBinding.Recognition.Pattern = "bad..example.com";
        Configuration.ProtocolBindings.push_back(std::move(InvalidBinding));
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::InvalidValue, "ProtocolBindings[0].CarrierId"});
    }

    TEST(PreviewTaskC11aBindingOrder, KeepsRecognitionMuxAndCapabilityOrder)
    {
        const auto BaseJson = MakeHttpConfigurationJson();
        auto RecognitionJson = ReplaceFirst(
            BaseJson, "\"Pattern\": \"example.com\"",
            "\"Pattern\": \"bad..example.com\"");
        RecognitionJson = ReplaceFirst(
            std::move(RecognitionJson), "\"MuxModes\": []", "\"MuxModes\": [\"Smux\"]");
        auto MuxJson = ReplaceFirst(
            BaseJson, "\"MuxModes\": []", "\"MuxModes\": [\"Unknown\"]");
        auto CapabilityJson = ReplaceFirst(
            BaseJson, "\"MuxModes\": []", "\"MuxModes\": [\"Smux\"]");
        CapabilityJson = ReplaceFirst(
            std::move(CapabilityJson), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");

        ExpectConfigurationError(
            ParseWithStaticSnapshot(RecognitionJson),
            {ConfigurationErrorCode::InvalidValue,
             "ProtocolBindings[0].Recognition.Pattern"});
        ExpectConfigurationError(
            ParseWithStaticSnapshot(MuxJson),
            {ConfigurationErrorCode::UnknownMuxMode, "ProtocolBindings[0].MuxModes[0]"});
        ExpectConfigurationError(
            ParseWithStaticSnapshot(CapabilityJson),
            {ConfigurationErrorCode::MissingCapability, "ProtocolBindings[0].MuxModes"});

        const auto Base = ParseWithoutSecrets(BaseJson);
        ASSERT_TRUE(Base.has_value());
        if (!Base)
        {
            return;
        }

        auto RecognitionConfiguration = *Base;
        RecognitionConfiguration.ProtocolBindings.front().Recognition.Pattern =
            "bad..example.com";
        RecognitionConfiguration.ProtocolBindings.front().MuxModes = {"Smux"};
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(RecognitionConfiguration),
            {ConfigurationErrorCode::InvalidValue,
             "ProtocolBindings[0].Recognition.Pattern"});

        auto MuxConfiguration = *Base;
        MuxConfiguration.ProtocolBindings.front().MuxModes = {"Unknown"};
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(MuxConfiguration),
            {ConfigurationErrorCode::UnknownMuxMode, "ProtocolBindings[0].MuxModes[0]"});

        auto CapabilityConfiguration = *Base;
        CapabilityConfiguration.ProtocolBindings.front().MuxModes = {"Smux"};
        CapabilityConfiguration.Accounts.front().Credential.clear();
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(CapabilityConfiguration),
            {ConfigurationErrorCode::MissingCapability, "ProtocolBindings[0].MuxModes"});
    }

    TEST(PreviewTaskC11cReferenceGraphOrder,
         KeepsMissingBindingReferenceAheadOfLaterDuplicateId)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"ProtocolId\": \"protocol-socks5\"",
            "\"ProtocolId\": \"missing-protocol\"");
        Json = ReplaceFirst(
            std::move(Json), "\"Id\": \"local\"", "\"Id\": \"tcp-main\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::MissingReference, "ProtocolBindings[0].ProtocolId"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.ProtocolBindings.front().ProtocolId = "missing-protocol";
        Configuration.Accounts.front().Id = "tcp-main";
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::MissingReference, "ProtocolBindings[0].ProtocolId"});
    }

    TEST(PreviewTaskC11cReferenceGraphOrder,
         KeepsDuplicateBindingIdAheadOfLaterMissingReference)
    {
        auto Json = ReplaceFirst(
            MakeFullConfigurationJson(), "\"Id\": \"binding-socks5\"",
            "\"Id\": \"tcp-main\"");
        Json = ReplaceFirst(
            std::move(Json), "\"ProtocolId\": \"protocol-socks5\"",
            "\"ProtocolId\": \"missing-protocol\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::DuplicateId, "ProtocolBindings[0].Id"});

        const auto ParsedConfiguration = MakeFullConfiguration();
        ASSERT_TRUE(ParsedConfiguration.has_value());
        if (!ParsedConfiguration)
        {
            return;
        }
        auto Configuration = *ParsedConfiguration;
        Configuration.ProtocolBindings.front().Id = "tcp-main";
        Configuration.ProtocolBindings.front().ProtocolId = "missing-protocol";
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::DuplicateId, "ProtocolBindings[0].Id"});
    }

    TEST(PreviewTaskC11cReferenceGraphOrder,
         KeepsCarrierAmbiguityAheadOfLaterAccountErrors)
    {
        auto Json = ReplaceFirst(
            MakeCarrierAmbiguityJson(), "\"Credential\": \"local-token\"",
            "\"Credential\": \"\"");
        Json = ReplaceFirst(
            std::move(Json), "\"Id\": \"local\"", "\"Id\": \"tcp-main\"");

        ExpectConfigurationError(
            ParseWithoutSecrets(Json),
            {ConfigurationErrorCode::InvalidValue, "Carriers[1].Match"});

        const auto Base = MakeFullConfiguration();
        ASSERT_TRUE(Base.has_value());
        if (!Base)
        {
            return;
        }
        auto Configuration = *Base;
        auto SecondaryCarrier = Configuration.Carriers.front();
        SecondaryCarrier.Id = "carrier-secondary";
        Configuration.Carriers.push_back(std::move(SecondaryCarrier));
        Configuration.ProtocolBindings.front().Priority = 0;
        auto SecondaryBinding = Configuration.ProtocolBindings.front();
        SecondaryBinding.Id = "binding-secondary";
        SecondaryBinding.CarrierId = "carrier-secondary";
        SecondaryBinding.Recognition.Pattern = "other.example.com";
        Configuration.ProtocolBindings.push_back(std::move(SecondaryBinding));
        Configuration.Accounts.front().Id = "tcp-main";
        Configuration.Accounts.front().Credential.clear();
        ExpectConfigurationError(
            ValidateWithStaticSnapshot(Configuration),
            {ConfigurationErrorCode::InvalidValue, "Carriers[1].Match"});
    }

} // namespace
