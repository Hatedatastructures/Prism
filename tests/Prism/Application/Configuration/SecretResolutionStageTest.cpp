/**
 * @file SecretResolutionStageTest.cpp
 * @brief Prism 配置跨解析、generation 构造的 SecretRef 阶段合同测试。
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Prism/Application/Configuration/Configuration.hpp>

namespace
{

    using Prism::Application::Configuration::ConfigurationErrorCode;
    using Prism::Application::Configuration::ConfigurationGeneration;
    using Prism::Application::Configuration::GenerationBuildOptions;
    using Prism::Application::Configuration::GenerationBuilder;
    using Prism::Application::Configuration::Parser;
    using Prism::Application::Configuration::PreparedGenerationBuildRequest;
    using Prism::Application::Configuration::ReloadCoordinator;
    using Prism::Application::Configuration::ReloadRequest;
    using Prism::Application::Configuration::SecretRefResolver;

    constexpr std::string_view SecretReference = "secret/account";
    constexpr std::string_view SecretValue = "account-secret";

    constexpr std::string_view ValidSecretJson = R"json(
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
  "Accounts": [{"Id": "secret-account", "SecretRef": "secret/account", "Credential": ""}],
  "Routes": [],
  "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
  "Statistics": {"Enabled": true, "Interval": 1000},
  "Operations": {"Enabled": true, "Endpoint": "127.0.0.1:9090", "Timeout": 1000},
  "HotReload": {"Enabled": true, "AckTimeout": 5000},
  "Shutdown": {"Timeout": 5000}
}
)json";

    auto MakeCountingResolver(std::size_t &Calls, const bool ResolveValue)
        -> SecretRefResolver::Callback
    {
        return [&Calls, ResolveValue](const std::string_view Reference)
            -> std::optional<std::string>
        {
            ++Calls;
            if (ResolveValue && Reference == SecretReference)
            {
                return std::string(SecretValue);
            }
            return std::nullopt;
        };
    }

    auto MakeMissingSecretWithLaterRouteJson() -> std::string
    {
        auto Json = std::string(ValidSecretJson);
        constexpr std::string_view EmptyRoutes = "  \"Routes\": [],";
        constexpr std::string_view InvalidRoute =
            "  \"Routes\": [{\"Id\": \"later-route\", \"Match\": \"\", \"Target\": \"\"}],";
        const auto Position = Json.find(EmptyRoutes);
        if (Position != std::string::npos)
        {
            Json.replace(Position, EmptyRoutes.size(), InvalidRoute);
        }
        return Json;
    }

    auto MakeRepeatedSecretReferencesJson() -> std::string
    {
        auto Json = std::string(ValidSecretJson);
        constexpr std::string_view Original =
            "  \"Accounts\": [{\"Id\": \"secret-account\", \"SecretRef\": \"secret/account\", \"Credential\": \"\"}],";
        constexpr std::string_view Repeated =
            "  \"Accounts\": [{\"Id\": \"secret-account\", \"SecretRef\": \"secret/account\", \"Credential\": \"\"},"
            "{\"Id\": \"secret-account-2\", \"SecretRef\": \"secret/account\", \"Credential\": \"\"},"
            "{\"Id\": \"external-account-1\", \"SecretRef\": \"secret/external\", \"Credential\": \"\"},"
            "{\"Id\": \"external-account-2\", \"SecretRef\": \"secret/external\", \"Credential\": \"\"}],";
        const auto Position = Json.find(Original);
        if (Position != std::string::npos)
        {
            Json.replace(Position, Original.size(), Repeated);
        }
        return Json;
    }

    auto MakeRepeatedAccountSecretReferencesJson() -> std::string
    {
        auto Json = std::string(ValidSecretJson);
        constexpr std::string_view Original =
            "  \"Accounts\": [{\"Id\": \"secret-account\", \"SecretRef\": \"secret/account\", \"Credential\": \"\"}],";
        constexpr std::string_view Repeated =
            "  \"Accounts\": [{\"Id\": \"secret-account\", \"SecretRef\": \"secret/account\", \"Credential\": \"\"},"
            "{\"Id\": \"secret-account-2\", \"SecretRef\": \"secret/account\", \"Credential\": \"\"}],";
        const auto Position = Json.find(Original);
        if (Position != std::string::npos)
        {
            Json.replace(Position, Original.size(), Repeated);
        }
        return Json;
    }

    class TemporaryJsonFile final
    {
    public:
        explicit TemporaryJsonFile(const std::string_view Json)
            : Root_(std::filesystem::temp_directory_path() /
                    ("PrismSecretStage-" +
                     std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))),
              Path_(Root_ / "configuration.json")
        {
            std::filesystem::create_directories(Root_);
            std::ofstream File(Path_, std::ios::binary);
            File.write(Json.data(), static_cast<std::streamsize>(Json.size()));
        }

        ~TemporaryJsonFile()
        {
            std::error_code Error;
            std::filesystem::remove_all(Root_, Error);
        }

        [[nodiscard]] auto Path() const -> const std::filesystem::path &
        {
            return Path_;
        }

    private:
        std::filesystem::path Root_;
        std::filesystem::path Path_;
    };

    auto SecretEquals(const std::span<const std::byte> Secret, const std::string_view Value) -> bool
    {
        return Secret.size() == Value.size() &&
               std::equal(Secret.begin(), Secret.end(),
                          reinterpret_cast<const std::byte *>(Value.data()));
    }

    TEST(PrismTaskC11d2SecretResolution,
         ReportsIndependentParserAndGenerationResolverCalls)
    {
        std::size_t ResolverCalls = 0;
        const auto Resolver = MakeCountingResolver(ResolverCalls, true);

        const auto Parsed = Parser::Parse({
            .Json = ValidSecretJson,
            .Options = {.Secrets = SecretRefResolver{Resolver}}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions BuildOptions;
        BuildOptions.Configuration = *Parsed;
        BuildOptions.SecretResolver = Resolver;
        const auto Generation = GenerationBuilder::Build(std::move(BuildOptions));

        ASSERT_TRUE(Generation.has_value()) << Generation.error().Message;
        EXPECT_EQ(ResolverCalls, 2U);
    }

    TEST(PrismTaskC11d2SecretResolution,
         ReportsMissingSecretBeforeASeparateLaterRouteError)
    {
        std::size_t ResolverCalls = 0;
        const auto Resolver = MakeCountingResolver(ResolverCalls, false);
        const auto Json = MakeMissingSecretWithLaterRouteJson();
        ASSERT_NE(Json.find("later-route"), std::string::npos);

        const auto Parsed = Parser::Parse({
            .Json = Json,
            .Options = {.Secrets = SecretRefResolver{Resolver}}});

        ASSERT_FALSE(Parsed.has_value());
        EXPECT_EQ(Parsed.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Parsed.error().Path, "Accounts[0].SecretRef");
    }

    TEST(PrismTaskC11d2SecretResolution,
         KeepsResolvedSecretAvailableAfterGenerationPinWithoutAnotherResolverCall)
    {
        const auto Parsed = Parser::Parse({
            .Json = ValidSecretJson,
            .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        std::size_t ResolverCalls = 0;
        GenerationBuildOptions BuildOptions;
        BuildOptions.Configuration = *Parsed;
        BuildOptions.SecretResolver = MakeCountingResolver(ResolverCalls, true);
        const auto Generation = GenerationBuilder::Build(std::move(BuildOptions));

        ASSERT_TRUE(Generation.has_value()) << Generation.error().Message;
        const auto Secret = (*Generation)->LookupSecret(SecretReference);
        ASSERT_EQ(Secret.size(), SecretValue.size());
        EXPECT_TRUE(std::equal(
            Secret.begin(), Secret.end(), reinterpret_cast<const std::byte *>(SecretValue.data())));
        EXPECT_EQ(ResolverCalls, 1U);

        const auto PinnedSecret = (*Generation)->LookupSecret(SecretReference);
        EXPECT_EQ(PinnedSecret.data(), Secret.data());
        EXPECT_EQ(ResolverCalls, 1U);
    }

    TEST(PrismTaskC11d4SecretResolution,
         PreparedFileResolvesRepeatedReferencesOnceAndTransfersThePinnedValue)
    {
        TemporaryJsonFile File(MakeRepeatedAccountSecretReferencesJson());
        std::size_t ResolverCalls = 0;
        const auto Resolver = [&ResolverCalls](const std::string_view Reference)
            -> std::optional<std::string>
        {
            ++ResolverCalls;
            return Reference == SecretReference ? std::optional<std::string>{SecretValue}
                                                : std::nullopt;
        };
        auto Prepared = Parser::PrepareFile({
            .Path = File.Path(),
            .Options = {.Secrets = SecretRefResolver{Resolver}}});

        ASSERT_TRUE(Prepared.has_value()) << Prepared.error().Message;
        EXPECT_TRUE(Prepared->Configuration().Secrets.empty());
        EXPECT_EQ(ResolverCalls, 1U);

        const auto Generation = GenerationBuilder::Build(
            PreparedGenerationBuildRequest{
                std::move(*Prepared), {}, {}, Prism::GenerationId{1}});

        ASSERT_TRUE(Generation.has_value()) << Generation.error().Message;
        EXPECT_TRUE((*Generation)->Configuration().Secrets.empty());
        const auto PinnedSecret = (*Generation)->LookupSecret(SecretReference);
        EXPECT_TRUE(SecretEquals(PinnedSecret, SecretValue));
        EXPECT_EQ((*Generation)->LookupSecret(SecretReference).data(), PinnedSecret.data());
        EXPECT_EQ(ResolverCalls, 1U);
    }

    TEST(PrismTaskC11d4SecretResolution,
         PreparedFileKeepsMissingSecretAheadOfALaterRouteError)
    {
        TemporaryJsonFile File(MakeMissingSecretWithLaterRouteJson());
        std::size_t ResolverCalls = 0;
        const auto Prepared = Parser::PrepareFile({
            .Path = File.Path(),
            .Options = {.Secrets = SecretRefResolver{
                            MakeCountingResolver(ResolverCalls, false)}}});

        ASSERT_FALSE(Prepared.has_value());
        EXPECT_EQ(Prepared.error().Code, ConfigurationErrorCode::UnresolvedSecret);
        EXPECT_EQ(Prepared.error().Path, "Accounts[0].SecretRef");
        EXPECT_EQ(ResolverCalls, 1U);
    }

    TEST(PrismTaskC11d4SecretResolution,
         DirectBuilderUsesInlineFirstFallsBackOnceAndDropsUnusedInlineValues)
    {
        const auto Parsed = Parser::Parse({
            .Json = MakeRepeatedSecretReferencesJson(),
            .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        auto Configuration = *Parsed;
        Configuration.Secrets.emplace("secret/account", "inline-account-secret");
        Configuration.Secrets.emplace("secret/external", "");
        Configuration.Secrets.emplace("secret/unused", "unused-inline-secret");
        std::size_t ResolverCalls = 0;
        GenerationBuildOptions BuildOptions;
        BuildOptions.Configuration = std::move(Configuration);
        BuildOptions.SecretResolver = [&ResolverCalls](const std::string_view Reference)
            -> std::optional<std::string>
        {
            ++ResolverCalls;
            return Reference == "secret/external"
                       ? std::optional<std::string>{"external-secret"}
                       : std::nullopt;
        };

        const auto Generation = GenerationBuilder::Build(std::move(BuildOptions));

        ASSERT_TRUE(Generation.has_value()) << Generation.error().Message;
        EXPECT_EQ(ResolverCalls, 1U);
        EXPECT_TRUE((*Generation)->Configuration().Secrets.empty());
        EXPECT_TRUE(SecretEquals((*Generation)->LookupSecret("secret/account"),
                                 "inline-account-secret"));
        EXPECT_TRUE(SecretEquals((*Generation)->LookupSecret("secret/external"),
                                 "external-secret"));
        EXPECT_TRUE((*Generation)->LookupSecret("secret/unused").empty());
    }

    TEST(PrismTaskC11d4SecretResolution,
         RejectedReloadLeavesThePublishedInlineSecretAndClearsCandidateConfiguration)
    {
        const auto Parsed = Parser::Parse({
            .Json = ValidSecretJson,
            .Options = {.CheckSecrets = false}});
        ASSERT_TRUE(Parsed.has_value()) << Parsed.error().Message;

        GenerationBuildOptions InitialOptions;
        InitialOptions.Configuration = *Parsed;
        InitialOptions.Configuration.Secrets.emplace("secret/account", "old-secret");
        const auto Initial = GenerationBuilder::Build(std::move(InitialOptions));
        ASSERT_TRUE(Initial.has_value()) << Initial.error().Message;

        ReloadRequest Request;
        Request.BaseGeneration = (*Initial)->Id();
        Request.Configuration = *Parsed;
        Request.Configuration.Secrets.emplace("secret/account", "new-secret");
        Request.Configuration.Secrets.emplace("secret/unused", "unused-secret");
        std::size_t ResolverCalls = 0;
        Request.SecretResolver = [&ResolverCalls](std::string_view)
            -> std::optional<std::string>
        {
            ++ResolverCalls;
            return std::nullopt;
        };
        ReloadCoordinator Coordinator;
        const auto Reloaded = Coordinator.Prepare(*Initial, std::move(Request));

        ASSERT_TRUE(Reloaded.has_value()) << Reloaded.error().Message;
        EXPECT_EQ(ResolverCalls, 0U);
        EXPECT_TRUE((*Reloaded)->Configuration().Secrets.empty());
        EXPECT_TRUE(SecretEquals((*Reloaded)->LookupSecret("secret/account"), "new-secret"));
        EXPECT_TRUE(SecretEquals((*Initial)->LookupSecret("secret/account"), "old-secret"));
    }

} // namespace
