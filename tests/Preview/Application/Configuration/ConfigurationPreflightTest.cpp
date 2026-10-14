/**
 * @file ConfigurationPreflightTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfigurationTestSupport.hpp"

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
        NoSniReality.Options = Preview::Contract::RealityOptions{
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
        Preview::Contract::ProtocolConfiguration Protocol;
        Protocol.Id = "protocol-socks5";
        Protocol.Name = "socks5";
        Protocol.Builtin = "socks5";
        Configuration.Protocols.push_back(Protocol);
        Preview::Contract::ProtocolBindingConfiguration FirstBinding;
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

