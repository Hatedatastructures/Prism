/**
 * @file ConfigurationStageOrderTest.cpp
 * @brief Prism 配置三阶段首错 corpus 测试。
 */

#include <gtest/gtest.h>

#include <Prism/Application/Application.hpp>
#include <Prism/Application/Configuration/ConfigurationParser.hpp>
#include <Prism/Application/Configuration/GenerationBuilder.hpp>
#include <Prism/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Prism/Composition/Builtin/Registry.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Prism::Application::Configuration::ConfigurationErrorCode;
    using Prism::Application::Configuration::GenerationBuilder;
    using Prism::Application::Configuration::ConfigurationParser;
    using Prism::Application::Configuration::ConfigurationValidator;
    using Prism::Application::StartupErrorCode;

    constexpr std::string_view ValidStageJson = R"json({
    "SchemaVersion": 1,
    "Runtime": {
        "WorkerCount": 2,
        "RequiredCapabilities": [],
        "SessionTimeout": 30000
    },
    "Listeners": {
        "Tcp": [{
            "Id": "tcp-main",
            "Address": "127.0.0.1",
            "Port": )json";

    constexpr std::string_view ValidStageJsonTail = R"json(,
            "Timeout": 5000
        }],
        "Udp": [],
        "Quic": [],
        "Timeout": 5000
    },
    "NativeTls": {
        "Enabled": false,
        "CertificateFile": "",
        "PrivateKeyFile": ""
    },
    "Builtins": [],
    "Protocols": [{
        "Id": "protocol-socks5",
        "Name": "socks5",
        "Builtin": "socks5",
        "Requires": []
    }],
    "Carriers": [],
    "ProtocolBindings": [{
        "Id": "binding-socks5",
        "ProtocolId": "protocol-socks5",
        "TcpEnabled": true,
        "UdpEnabled": false,
        "MuxModes": [],
        "Priority": 0,
        "Recognition": {
            "Pattern": "",
            "Fallback": false
        }
    }],
    "Accounts": [{
        "Id": "local",
        "SecretRef": "",
        "Credential": "local-token",
        "Credentials": {}
    }],
    "Routes": [],
    "Dns": {
        "Servers": ["1.1.1.1"],
        "Timeout": 1000
    },
    "Logging": {
        "Level": "Trace",
        "Directory": "logs",
        "FileName": "prism-stage.log",
        "RenderMode": "CompactHuman",
        "Console": false
    },
    "Statistics": {
        "Enabled": true,
        "Interval": 1000
    },
    "Operations": {
        "Enabled": true,
        "Endpoint": "127.0.0.1:9090",
        "Timeout": 1000
    },
    "HotReload": {
        "Enabled": false,
        "AckTimeout": 5000
    },
    "Shutdown": {
        "Timeout": 5000
    }
})json";

    struct Replacement final
    {
        std::string_view From;
        std::string_view To;
    };

    struct ExpectedConfigurationError final
    {
        ConfigurationErrorCode Code;
        std::string_view Path;
        std::string_view MessageKeyword{};
    };

    struct ExpectedStartupError final
    {
        StartupErrorCode Code;
        std::string_view Path;
        std::string_view MessageKeyword{};
    };

    auto ReplaceFirst(std::string Value, const Replacement Patch) -> std::string
    {
        const auto Position = Value.find(Patch.From);
        if (Position != std::string::npos)
        {
            Value.replace(Position, Patch.From.size(), Patch.To);
        }
        return Value;
    }

    auto MakeStageJson(const std::uint16_t Port) -> std::string
    {
        return std::string(ValidStageJson) + std::to_string(Port) +
               std::string(ValidStageJsonTail);
    }

    auto MakeStaticBuiltinSnapshot()
        -> std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot>
    {
        auto RegistryValue = Prism::Composition::Builtin::MakeStaticBuiltinRegistry();
        if (!Prism::Composition::Builtin::RegisterStaticBuiltins(RegistryValue, {}))
        {
            return nullptr;
        }
        const auto Frozen = RegistryValue.Freeze(
            Prism::Composition::Builtin::FreezeRequest{});
        return Frozen ? *Frozen : nullptr;
    }

    auto FindFreePort() -> std::uint16_t
    {
        Net::io_context Io;
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
        return Acceptor.local_endpoint().port();
    }

    class TemporaryConfiguration final
    {
    public:
        explicit TemporaryConfiguration(std::string Json)
            : Path_(std::filesystem::temp_directory_path() /
                    ("Prism-ConfigurationStageOrder-" +
                     std::to_string(std::hash<std::string>{}(Json)) + ".json"))
        {
            std::ofstream File(Path_, std::ios::binary);
            File << Json;
        }

        ~TemporaryConfiguration()
        {
            std::error_code Error;
            std::filesystem::remove(Path_, Error);
        }

        TemporaryConfiguration(const TemporaryConfiguration &) = delete;
        auto operator=(const TemporaryConfiguration &) -> TemporaryConfiguration & = delete;

        [[nodiscard]] auto Path() const -> const std::filesystem::path &
        {
            return Path_;
        }

    private:
        std::filesystem::path Path_;
    };

    template <typename Result>
    auto ExpectConfigurationError(const Result &Value,
                                  const ExpectedConfigurationError Expected) -> void
    {
        ASSERT_FALSE(Value.has_value());
        if (Value.has_value())
        {
            return;
        }
        EXPECT_EQ(Value.error().Code, Expected.Code);
        EXPECT_EQ(Value.error().Path, Expected.Path);
        if (!Expected.MessageKeyword.empty())
        {
            EXPECT_NE(Value.error().Message.find(Expected.MessageKeyword), std::string::npos);
        }
    }

    auto ExpectStartupError(
        const std::expected<Prism::Application::Readiness,
                            Prism::Application::StartupError> &Value,
        const ExpectedStartupError Expected) -> void
    {
        ASSERT_FALSE(Value.has_value());
        if (Value.has_value())
        {
            return;
        }
        EXPECT_EQ(Value.error().Code, Expected.Code);
        EXPECT_EQ(Value.error().Path, Expected.Path);
        if (!Expected.MessageKeyword.empty())
        {
            EXPECT_NE(Value.error().Message.find(Expected.MessageKeyword), std::string::npos);
        }
    }

} // namespace

TEST(PrismTaskC11d0StageOrder,
     KeepsBindingReferenceAheadOfLaterUnsupportedRouteInParserAndGeneration)
{
    auto Json = MakeStageJson(1080);
    Json = ReplaceFirst(std::move(Json),
                        {"\"ProtocolId\": \"protocol-socks5\"",
                         "\"ProtocolId\": \"missing-protocol\""});
    Json = ReplaceFirst(std::move(Json),
                        {"\"Routes\": [],",
                         "\"Routes\": [{\"Id\":\"route-default\",\"Match\":\"*\","
                         "\"Target\":\"direct\",\"Requires\":[]}],"});

    const auto Parsed = ConfigurationParser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
    ExpectConfigurationError(
        Parsed,
        {ConfigurationErrorCode::MissingReference,
         "ProtocolBindings[0].ProtocolId"});

    const auto Base = ConfigurationParser::Parse({.Json = ReplaceFirst(
                                               Json,
                                               {"\"ProtocolId\": \"missing-protocol\"",
                                                "\"ProtocolId\": \"protocol-socks5\""}),
                                     .Options = {.CheckSecrets = false}});
    ASSERT_TRUE(Base.has_value());
    if (!Base)
    {
        return;
    }
    auto Configuration = *Base;
    Configuration.ProtocolBindings.front().ProtocolId = "missing-protocol";
    const auto Snapshot = MakeStaticBuiltinSnapshot();
    ASSERT_NE(Snapshot, nullptr);
    if (Snapshot == nullptr)
    {
        return;
    }

    const auto Generation = GenerationBuilder::Build(
        Prism::Application::Configuration::GenerationBuildOptions{
            std::move(Configuration), Snapshot, {}, {}, Prism::GenerationId{1}});
    ExpectConfigurationError(
        Generation,
        {ConfigurationErrorCode::MissingReference,
         "ProtocolBindings[0].ProtocolId"});

    TemporaryConfiguration ConfigurationFile(Json);
    Prism::Application::Options Options;
    Options.ConfigurationPath = ConfigurationFile.Path();
    Prism::Application::Application Application(std::move(Options));
    const auto Result = Application.Start();
    ExpectStartupError(Result,
                       {StartupErrorCode::InvalidConfiguration,
                        "ProtocolBindings[0].ProtocolId"});
    EXPECT_FALSE(Application.IsReady());
}

TEST(PrismTaskC11d0StageOrder,
     KeepsRouteSupportRejectionAfterParserAndGenerationHavePassed)
{
    const auto Port = FindFreePort();
    const auto Json = ReplaceFirst(
        MakeStageJson(Port),
        {"\"Routes\": [],",
         "\"Routes\": [{\"Id\":\"route-default\",\"Match\":\"*\","
         "\"Target\":\"direct\",\"Requires\":[]}],"});

    const auto Parsed = ConfigurationParser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
    ASSERT_TRUE(Parsed.has_value());
    if (!Parsed)
    {
        return;
    }

    const auto Snapshot = MakeStaticBuiltinSnapshot();
    ASSERT_NE(Snapshot, nullptr);
    if (Snapshot == nullptr)
    {
        return;
    }
    const auto Generation = GenerationBuilder::Build(
        Prism::Application::Configuration::GenerationBuildOptions{
            *Parsed, Snapshot, {}, {}, Prism::GenerationId{1}});
    ASSERT_TRUE(Generation.has_value())
        << (Generation ? std::string{} : Generation.error().Path + ": " +
                                                   Generation.error().Message);

    TemporaryConfiguration ConfigurationFile(Json);
    Prism::Application::Options Options;
    Options.ConfigurationPath = ConfigurationFile.Path();
    Prism::Application::Application Application(std::move(Options));
    const auto Result = Application.Start();

    ExpectStartupError(Result,
                       {StartupErrorCode::UnsupportedService,
                        "Routes",
                        "not wired into Prism startup"});
    EXPECT_FALSE(Application.IsReady());
}

TEST(PrismTaskC11d0StageOrder,
     KeepsBuiltinProviderRejectionAfterParserAndGenerationHavePassed)
{
    const auto Port = FindFreePort();
    const auto Json = ReplaceFirst(
        MakeStageJson(Port),
        {"\"Builtins\": [],",
         "\"Builtins\": [{\"Id\":\"builtin-socks5\",\"Kind\":\"protocol\","
         "\"Name\":\"socks5\",\"Requires\":[],\"Provides\":[]}],"});

    const auto Parsed = ConfigurationParser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
    ASSERT_TRUE(Parsed.has_value());
    if (!Parsed)
    {
        return;
    }

    const auto Snapshot = MakeStaticBuiltinSnapshot();
    ASSERT_NE(Snapshot, nullptr);
    if (Snapshot == nullptr)
    {
        return;
    }
    const auto Generation = GenerationBuilder::Build(
        Prism::Application::Configuration::GenerationBuildOptions{
            *Parsed, Snapshot, {}, {}, Prism::GenerationId{1}});
    ASSERT_TRUE(Generation.has_value())
        << (Generation ? std::string{} : Generation.error().Path + ": " +
                                                   Generation.error().Message);

    TemporaryConfiguration ConfigurationFile(Json);
    Prism::Application::Options Options;
    Options.ConfigurationPath = ConfigurationFile.Path();
    Prism::Application::Application Application(std::move(Options));
    const auto Result = Application.Start();

    ExpectStartupError(Result,
                       {StartupErrorCode::UnsupportedService,
                        "Builtins.builtin-socks5",
                        "no callable Prism callback"});
    EXPECT_FALSE(Application.IsReady());
}

TEST(PrismTaskC11d0StageOrder,
     PreservesCurrentValidationOfDisabledOperationsEndpoint)
{
    auto Json = MakeStageJson(1080);
    Json = ReplaceFirst(std::move(Json),
                        {"\"Operations\": {\n        \"Enabled\": true,",
                         "\"Operations\": {\n        \"Enabled\": false,"});
    Json = ReplaceFirst(std::move(Json),
                        {"\"Endpoint\": \"127.0.0.1:9090\"",
                         "\"Endpoint\": \"invalid-endpoint\""});

    const auto Parsed = ConfigurationParser::Parse({.Json = Json, .Options = {.CheckSecrets = false}});
    ExpectConfigurationError(
        Parsed,
        {ConfigurationErrorCode::InvalidValue, "Operations.Endpoint"});

    TemporaryConfiguration ConfigurationFile(Json);
    Prism::Application::Options Options;
    Options.ConfigurationPath = ConfigurationFile.Path();
    Prism::Application::Application Application(std::move(Options));
    const auto Result = Application.Start();
    ExpectStartupError(Result,
                       {StartupErrorCode::InvalidConfiguration,
                        "Operations.Endpoint"});
    EXPECT_FALSE(Application.IsReady());
}
