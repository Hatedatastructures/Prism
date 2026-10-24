/**
 * @file ConfigurationSchemaTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ConfigurationTestSupport.hpp"

TEST(PrismTask3Configuration, ParsesTheAuthoritativePascalCaseSchema)
    {
        const auto Parsed = ConfigurationParser::ParseJson(ValidJson);

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        EXPECT_EQ(Parsed->SchemaVersion, 1U);
        EXPECT_EQ(Parsed->Runtime.WorkerCount, 2U);
        EXPECT_EQ(Parsed->Listeners.Tcp.front().Port, 1080U);
        EXPECT_EQ(Parsed->Listeners.Udp.front().Port, 1081U);
        EXPECT_EQ(Parsed->Listeners.Quic.front().Port, 1081U);
        EXPECT_EQ(Parsed->Accounts.front().Id, "local");
    }

TEST(PrismTask3Configuration, MapsNativeTlsEchConfigurationFields)
    {
        const auto Json = ReplaceFirst(
            std::string(ValidJson), "  \"Builtins\": [],",
            "  \"NativeTls\": {\"Enabled\": true, \"CertificateFile\": \"cert.pem\", "
            "\"PrivateKeyFile\": \"key.pem\", \"Ech\": {\"Enabled\": true, "
            "\"PrivateKeyFile\": \"ech.key\", \"EchConfigFile\": \"ech.config\"}},\n"
            "  \"Builtins\": [],");

        const auto Parsed = ConfigurationParser::ParseJson(Json);

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        EXPECT_TRUE(Parsed->NativeTls.Enabled);
        EXPECT_EQ(Parsed->NativeTls.CertificateFile, "cert.pem");
        EXPECT_EQ(Parsed->NativeTls.PrivateKeyFile, "key.pem");
        EXPECT_TRUE(Parsed->NativeTls.Ech.Enabled);
        EXPECT_EQ(Parsed->NativeTls.Ech.PrivateKeyFile, "ech.key");
        EXPECT_EQ(Parsed->NativeTls.Ech.EchConfigFile, "ech.config");
    }

TEST(PrismTask3Configuration, RejectsNativeTlsEchWithoutCompleteServerKeyFiles)
    {
        const auto Json = ReplaceFirst(
            std::string(ValidJson), "  \"Builtins\": [],",
            "  \"NativeTls\": {\"Enabled\": true, \"CertificateFile\": \"cert.pem\", "
            "\"PrivateKeyFile\": \"key.pem\", \"Ech\": {\"Enabled\": true, "
            "\"PrivateKeyFile\": \"ech.key\"}},\n  \"Builtins\": [],");

        const auto Parsed = ConfigurationParser::ParseJson(Json);

        ASSERT_FALSE(Parsed.has_value());
        EXPECT_EQ(Parsed.error().Code, ConfigurationErrorCode::MissingField);
        EXPECT_EQ(Parsed.error().Path, "NativeTls.Ech");
    }

TEST(PrismTaskLoggingConfiguration, ParsesPascalCaseLoggingAndTraceFields)
    {
        const auto Parsed = ConfigurationParser::ParseJson(ValidJson);

        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
        EXPECT_EQ(Parsed->Logging.Level, "Info");
        EXPECT_EQ(Parsed->Logging.RenderMode, "CompactHuman");
        EXPECT_EQ(Parsed->Logging.Directory, "logs");
        EXPECT_EQ(Parsed->Logging.FileName, "prism.log");
        EXPECT_FALSE(Parsed->Logging.Console);
        EXPECT_EQ(Parsed->Logging.RotateBytes, 67108864U);
        EXPECT_EQ(Parsed->Logging.RotateFiles, 8U);
        EXPECT_EQ(Parsed->Logging.FlushIntervalMs, 250U);
        EXPECT_TRUE(Parsed->Trace.IncludeCorrelation);
        EXPECT_TRUE(Parsed->Trace.IncludeWorker);
        EXPECT_TRUE(Parsed->Trace.IncludeSession);
        EXPECT_FALSE(Parsed->Trace.IncludeStream);
    }

TEST(PrismTaskLoggingConfiguration, DefaultsUseFileLoggingAndDisableConsole)
    {
        const auto Defaults =
            Prism::Application::Configuration::PrismConfiguration::Defaults();

        EXPECT_EQ(Defaults.Logging.Level, "Info");
        EXPECT_EQ(Defaults.Logging.RenderMode, "CompactHuman");
        EXPECT_EQ(Defaults.Logging.Directory, "logs");
        EXPECT_EQ(Defaults.Logging.FileName, "prism.log");
        EXPECT_FALSE(Defaults.Logging.Console);
        EXPECT_EQ(Defaults.Logging.RotateBytes, 67108864U);
        EXPECT_EQ(Defaults.Logging.RotateFiles, 8U);
        EXPECT_EQ(Defaults.Logging.FlushIntervalMs, 250U);
        EXPECT_TRUE(Defaults.Trace.IncludeCorrelation);
        EXPECT_TRUE(Defaults.Trace.IncludeWorker);
        EXPECT_TRUE(Defaults.Trace.IncludeSession);
        EXPECT_FALSE(Defaults.Trace.IncludeStream);
    }

TEST(PrismTaskLoggingConfiguration, AcceptsTheThreeExactRenderModes)
    {
        constexpr std::array<std::string_view, 3> Modes{
            "CompactHuman", "HumanWithFields", "Structured"};
        for (const auto Mode : Modes)
        {
            const auto Replacement = std::string{"\"Level\": \"Info\", \"RenderMode\": \""} +
                                     std::string(Mode) + "\",";
            const auto Json = ReplaceFirst(
                std::string(ValidJson), "\"Level\": \"Info\",", Replacement);
            const auto Parsed = ConfigurationParser::ParseJson(Json);
            ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;
            EXPECT_EQ(Parsed->Logging.RenderMode, Mode);
        }
    }

TEST(PrismTask3Configuration, RejectsUnknownFieldsAtEverySchemaBoundary)
    {
        const auto UnknownTopLevel = ReplaceFirst(
            std::string(ValidJson), "\n  \"SchemaVersion\": 1,", "\n  \"Unknown\": true,\n  \"SchemaVersion\": 1,");
        const auto UnknownNested = ReplaceFirst(
            std::string(ValidJson), "\"WorkerCount\": 2,", "\"WorkerCount\": 2, \"Unknown\": true,");

        const auto TopResult = ConfigurationParser::ParseJson(UnknownTopLevel);
        const auto NestedResult = ConfigurationParser::ParseJson(UnknownNested);

        ASSERT_FALSE(TopResult.has_value());
        EXPECT_EQ(TopResult.error().Code, ConfigurationErrorCode::UnknownField);
        ASSERT_FALSE(NestedResult.has_value());
        EXPECT_EQ(NestedResult.error().Code, ConfigurationErrorCode::UnknownField);
    }

TEST(PrismTask3Configuration, ReportsMissingRequiredTopLevelFieldPath)
    {
        const auto MissingSchemaVersion = ReplaceFirst(
            std::string(ValidJson), "  \"SchemaVersion\": 1,\n", "");

        const auto Result = ConfigurationParser::ParseJson(MissingSchemaVersion);

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingField);
        EXPECT_EQ(Result.error().Path, "SchemaVersion");
    }

TEST(PrismTask3Configuration, RetainsLastValueForRepeatedTopLevelAndNestedKeys)
    {
        const auto RepeatedTopLevel = ReplaceFirst(
            std::string(ValidJson), "  \"SchemaVersion\": 1,\n",
            "  \"SchemaVersion\": 0,\n  \"SchemaVersion\": 1,\n");
        const auto RepeatedNested = ReplaceFirst(
            std::string(ValidJson), "    \"WorkerCount\": 2,\n",
            "    \"WorkerCount\": 2,\n    \"WorkerCount\": 3,\n");

        const auto TopLevelResult = ConfigurationParser::ParseJson(RepeatedTopLevel);
        const auto NestedResult = ConfigurationParser::ParseJson(RepeatedNested);

        ASSERT_TRUE(TopLevelResult.has_value()) << TopLevelResult.error().Message;
        EXPECT_EQ(TopLevelResult->SchemaVersion, 1U);
        ASSERT_TRUE(NestedResult.has_value()) << NestedResult.error().Message;
        EXPECT_EQ(NestedResult->Runtime.WorkerCount, 3U);
    }

TEST(PrismTask3Configuration, ReportsRequiredFieldBeforeOtherRootErrors)
    {
        const auto MissingWithUnknown = ReplaceFirst(
            std::string(ValidJson), "  \"SchemaVersion\": 1,\n", "  \"Unknown\": true,\n");
        auto MissingWithWrongType = ReplaceFirst(
            std::string(ValidJson), "  \"SchemaVersion\": 1,\n", "");
        MissingWithWrongType = ReplaceFirst(
            std::move(MissingWithWrongType), "\"WorkerCount\": 2", "\"WorkerCount\": \"2\"");

        const auto UnknownResult = ConfigurationParser::ParseJson(MissingWithUnknown);
        const auto WrongTypeResult = ConfigurationParser::ParseJson(MissingWithWrongType);

        const auto ExpectMissingSchemaVersion = [](const auto &Result)
        {
            ASSERT_FALSE(Result.has_value());
            EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::MissingField);
            EXPECT_EQ(Result.error().Path, "SchemaVersion");
        };
        ExpectMissingSchemaVersion(UnknownResult);
        ExpectMissingSchemaVersion(WrongTypeResult);
    }

TEST(PrismTask3Configuration, PreservesParseCodeForObjectShapeErrors)
    {
        const auto InvalidDnsShape = ReplaceFirst(
            std::string(ValidJson), "\"Dns\": {\"Servers\": [\"1.1.1.1\"], \"Timeout\": 1000}",
            "\"Dns\": []");

        const auto Result = ConfigurationParser::ParseJson(InvalidDnsShape);

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::Parse);
        EXPECT_TRUE(Result.error().Path.empty());
    }

TEST(PrismTask3Configuration, AppliesSchemaDefaultsDuringDecode)
    {
        const auto Result = ConfigurationParser::ParseJson(ValidJson);

        ASSERT_TRUE(Result.has_value()) << Result.error().Message;
        EXPECT_EQ(Result->Logging.RenderMode, "CompactHuman");
        EXPECT_EQ(Result->Recognition.Mode, "MixedTrial");
        EXPECT_FALSE(Result->NativeTls.Enabled);
        EXPECT_EQ(Result->Runtime.SessionTimeout, 30000U);
    }

TEST(PrismTask3Configuration, RejectsInvalidNumericTypesAndBounds)
    {
        const auto WrongType = ReplaceFirst(
            std::string(ValidJson), "\"WorkerCount\": 2", "\"WorkerCount\": \"2\"");
        const auto OutOfRange = ReplaceFirst(
            std::string(ValidJson), "\"Port\": 1080", "\"Port\": 65536");

        const auto WrongTypeResult = ConfigurationParser::ParseJson(WrongType);
        const auto OutOfRangeResult = ConfigurationParser::ParseJson(OutOfRange);

        ASSERT_FALSE(WrongTypeResult.has_value());
        EXPECT_EQ(WrongTypeResult.error().Code, ConfigurationErrorCode::InvalidType);
        ASSERT_FALSE(OutOfRangeResult.has_value());
        EXPECT_EQ(OutOfRangeResult.error().Code, ConfigurationErrorCode::InvalidType);
    }

TEST(PrismTaskLoggingConfiguration, RejectsUnknownLoggingAndTraceFields)
    {
        const auto UnknownLogging = ReplaceFirst(
            std::string(ValidJson), "\"Level\": \"Info\",",
            "\"Level\": \"Info\", \"Unknown\": true,");
        const auto UnknownTrace = ReplaceFirst(
            std::string(ValidJson), "\"IncludeStream\": false",
            "\"IncludeStream\": false, \"Unknown\": true");

        const auto LoggingResult = ConfigurationParser::ParseJson(UnknownLogging);
        const auto TraceResult = ConfigurationParser::ParseJson(UnknownTrace);

        ASSERT_FALSE(LoggingResult.has_value());
        EXPECT_EQ(LoggingResult.error().Code, ConfigurationErrorCode::UnknownField);
        ASSERT_FALSE(TraceResult.has_value());
        EXPECT_EQ(TraceResult.error().Code, ConfigurationErrorCode::UnknownField);
    }

TEST(PrismTaskLoggingConfiguration, RejectsInvalidLoggingValues)
    {
        const auto InvalidLevel = ReplaceFirst(
            std::string(ValidJson), "\"Level\": \"Info\"", "\"Level\": \"Verbose\"");
        const auto InvalidDirectory = ReplaceFirst(
            std::string(ValidJson), "\"Directory\": \"logs\"", "\"Directory\": \"\"");
        const auto InvalidFileName = ReplaceFirst(
            std::string(ValidJson), "\"FileName\": \"prism.log\"",
            "\"FileName\": \"nested/prism.log\"");
        const auto InvalidRotateBytes = ReplaceFirst(
            std::string(ValidJson), "\"RotateBytes\": 67108864", "\"RotateBytes\": 0");
        const auto InvalidRotateFiles = ReplaceFirst(
            std::string(ValidJson), "\"RotateFiles\": 8", "\"RotateFiles\": 0");
        const auto InvalidFlushInterval = ReplaceFirst(
            std::string(ValidJson), "\"FlushIntervalMs\": 250", "\"FlushIntervalMs\": 0");
        const auto InvalidRenderMode = ReplaceFirst(
            std::string(ValidJson), "\"Level\": \"Info\",",
            "\"Level\": \"Info\", \"RenderMode\": \"structured\",");

        const auto LevelResult = ConfigurationParser::ParseJson(InvalidLevel);
        const auto DirectoryResult = ConfigurationParser::ParseJson(InvalidDirectory);
        const auto FileNameResult = ConfigurationParser::ParseJson(InvalidFileName);
        const auto RotateBytesResult = ConfigurationParser::ParseJson(InvalidRotateBytes);
        const auto RotateFilesResult = ConfigurationParser::ParseJson(InvalidRotateFiles);
        const auto FlushIntervalResult = ConfigurationParser::ParseJson(InvalidFlushInterval);
        const auto RenderModeResult = ConfigurationParser::ParseJson(InvalidRenderMode);

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
        ASSERT_FALSE(RenderModeResult.has_value());
        EXPECT_EQ(RenderModeResult.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(RenderModeResult.error().Path, "Logging.RenderMode");
    }

TEST(PrismTaskLoggingConfiguration, RejectsInvalidLoggingTypes)
    {
        const auto InvalidConsole = ReplaceFirst(
            std::string(ValidJson), "\"Console\": false", "\"Console\": \"false\"");

        const auto Result = ConfigurationParser::ParseJson(InvalidConsole);

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidType);
    }

TEST(PrismTask3Configuration, RejectsDuplicateIds)
    {
        const auto Json = ReplaceFirst(
            std::string(ValidJson),
            "\"Routes\": [],",
            "\"Routes\": [{\"Id\": \"same\", \"Match\": \"*\", \"Target\": \"direct\", \"Requires\": []},"
            "{\"Id\": \"same\", \"Match\": \"example\", \"Target\": \"direct\", \"Requires\": []}],");

        const auto Result = ConfigurationParser::ParseJson(Json);

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::DuplicateId);
    }

TEST(PrismTask3Configuration, RejectsInvalidPortsAndTimeouts)
    {
        const auto BadPort = ReplaceFirst(std::string(ValidJson), "\"Port\": 1080", "\"Port\": 0");
        const auto BadTimeout = ReplaceFirst(
            std::string(ValidJson), "\"Timeout\": 5000", "\"Timeout\": 0");

        const auto PortResult = ConfigurationParser::ParseJson(BadPort);
        const auto TimeoutResult = ConfigurationParser::ParseJson(BadTimeout);

        ASSERT_FALSE(PortResult.has_value());
        EXPECT_EQ(PortResult.error().Code, ConfigurationErrorCode::InvalidValue);
        ASSERT_FALSE(TimeoutResult.has_value());
        EXPECT_EQ(TimeoutResult.error().Code, ConfigurationErrorCode::InvalidValue);
    }

TEST(PrismTaskDConfiguration, RequiresOneTcpListenerAndOneSharedUdpQuicEntry)
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

        const auto NoTcpResult = ConfigurationParser::ParseJson(NoTcp);
        const auto TwoTcpResult = ConfigurationParser::ParseJson(TwoTcp);
        const auto MismatchedResult = ConfigurationParser::ParseJson(MismatchedQuic);

        ASSERT_FALSE(NoTcpResult.has_value());
        EXPECT_EQ(NoTcpResult.error().Path, "Listeners.Tcp");
        ASSERT_FALSE(TwoTcpResult.has_value());
        EXPECT_EQ(TwoTcpResult.error().Path, "Listeners.Tcp");
        ASSERT_FALSE(MismatchedResult.has_value());
        EXPECT_EQ(MismatchedResult.error().Path, "Listeners.Quic[0]");
    }

TEST(PrismTaskDConfiguration, RejectsSecondDeclaredQuicListenerBeforeProjection)
    {
        const auto Json = ReplaceFirst(std::string(ValidJson),
            "\"Quic\": [{\"Id\": \"quic-main\", \"Address\": \"127.0.0.1\", \"Port\": 1081, \"Timeout\": 5000}]",
            "\"Quic\": [{\"Id\":\"quic-main\",\"Address\":\"127.0.0.1\",\"Port\":1081,\"Timeout\":5000},"
            "{\"Id\":\"quic-second\",\"Address\":\"127.0.0.1\",\"Port\":1082,\"Timeout\":5000}]");
        const auto Result = ConfigurationParser::ParseJson(Json);
        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Listeners");
    }

TEST(PrismTaskDConfiguration, RejectsMultipleProtocolsOnSharedQuicListener)
    {
        const auto TwoQuicProtocols = ReplaceFirst(
            std::string(ValidJson),
            "\"Protocols\": [],",
            "\"Protocols\": [{\"Id\":\"protocol-hysteria2\",\"Name\":\"hysteria2\",\"Builtin\":\"hysteria2\",\"Requires\":[],\"Quic\":{\"Alpn\":\"h3\",\"ServerName\":\"hysteria.example\",\"CredentialSecretRef\":\"secret/quic/password\",\"MaxStreams\":32,\"MaxDatagrams\":64}},{\"Id\":\"protocol-tuic\",\"Name\":\"tuic\",\"Builtin\":\"tuic\",\"Requires\":[],\"Quic\":{\"Alpn\":\"h3\",\"ServerName\":\"tuic.example\",\"CredentialSecretRef\":\"secret/quic/password\",\"MaxStreams\":32,\"MaxDatagrams\":64,\"Uuid\":\"123e4567-e89b-12d3-a456-426614174000\"}}],");
        const auto Json = ReplaceFirst(
            TwoQuicProtocols,
            "\"Accounts\":",
            "\"Secrets\": {\"secret/quic/password\": \"quic-password\"},\n  \"Accounts\":");

        const auto Result = ConfigurationParser::ParseJson(Json);

        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        EXPECT_EQ(Result.error().Path, "Protocols[1].Builtin");
    }

TEST(PrismTaskDConfiguration, ValidatesOperationsEndpointAddressAndPort)
    {
        const auto InvalidAddress = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "0.0.0.0:9090");
        const auto InvalidPort = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "127.0.0.1:65536");
        const auto MissingPort = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "127.0.0.1");
        const auto InvalidIpv6 = ReplaceFirst(
            std::string(ValidJson), "127.0.0.1:9090", "::1:9090");

        const auto AddressResult = ConfigurationParser::ParseJson(InvalidAddress);
        const auto PortResult = ConfigurationParser::ParseJson(InvalidPort);
        const auto MissingPortResult = ConfigurationParser::ParseJson(MissingPort);
        const auto Ipv6Result = ConfigurationParser::ParseJson(InvalidIpv6);

        for (const auto &Result : {AddressResult, PortResult, MissingPortResult, Ipv6Result})
        {
            ASSERT_FALSE(Result.has_value());
            EXPECT_EQ(Result.error().Path, "Operations.Endpoint");
            EXPECT_EQ(Result.error().Code, ConfigurationErrorCode::InvalidValue);
        }
    }

