/**
 * @file PreviewConfigurationTest.cpp
 * @brief PrismPreview 配置 wrapper 与 effective mode 契约测试
 */

#include <gtest/gtest.h>

#include <filesystem>
#include <string_view>

#include <prism/preview/Configuration.hpp>

namespace
{

    namespace PreviewBridge = psm::preview;

    TEST(PreviewConfigurationContract, DefaultsEnableExplicitHybridFallback)
    {
        const auto Config = PreviewBridge::Configuration::Defaults();
        const auto Modes = Config.EffectiveModes();

        EXPECT_EQ(Config.Preview.Mode, "hybrid");
        EXPECT_EQ(Config.Preview.ShutdownTimeoutMs, 5000U);
        EXPECT_EQ(Config.Preview.SessionDrainTimeoutMs, 5000U);
        EXPECT_TRUE(Modes.UsePreviewRuntime);
        EXPECT_TRUE(Modes.UseProductionFallback);
        EXPECT_FALSE(Modes.PreviewProtocolAdapters);
    }

    TEST(PreviewConfigurationContract, RejectsUnknownKeysAndUnsupportedModes)
    {
        const auto Unknown = PreviewBridge::Configuration::ParseJson(
            R"({"preview":{"mode":"hybrid"},"unexpected":true})");
        EXPECT_FALSE(Unknown.has_value());

        const auto Unsupported = PreviewBridge::Configuration::ParseJson(
            R"({"preview":{"mode":"preview_only"}})");
        EXPECT_FALSE(Unsupported.has_value());
    }

    TEST(PreviewConfigurationContract, EnablesOnlySocks5PreviewAdapters)
    {
        const auto Parsed = PreviewBridge::Configuration::ParseJson(
            R"({"preview":{"mode":"socks5_preview"}})");
        ASSERT_TRUE(Parsed.has_value());
        const auto Modes = Parsed->EffectiveModes();

        EXPECT_TRUE(Modes.UsePreviewRuntime);
        EXPECT_TRUE(Modes.UseProductionFallback);
        EXPECT_TRUE(Modes.PreviewProtocolAdapters);
    }

    TEST(PreviewConfigurationContract, EnablesOnlyHttpPreviewAdapters)
    {
        const auto Parsed = PreviewBridge::Configuration::ParseJson(
            R"({"preview":{"mode":"http_preview"}})");
        ASSERT_TRUE(Parsed.has_value());
        const auto Modes = Parsed->EffectiveModes();

        EXPECT_TRUE(Modes.UsePreviewRuntime);
        EXPECT_TRUE(Modes.UseProductionFallback);
        EXPECT_TRUE(Modes.PreviewProtocolAdapters);
    }

    TEST(PreviewConfigurationContract, ParsesStrictPreviewTimeouts)
    {
        const auto Parsed = PreviewBridge::Configuration::ParseJson(
            R"({"preview":{"mode":"production_fallback", "shutdown_timeout_ms":1200,
                              "session_drain_timeout_ms":2400}})");
        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->Preview.Mode, "production_fallback");
        EXPECT_EQ(Parsed->Preview.ShutdownTimeoutMs, 1200U);
        EXPECT_EQ(Parsed->Preview.SessionDrainTimeoutMs, 2400U);
        EXPECT_FALSE(Parsed->EffectiveModes().UsePreviewRuntime);
        EXPECT_TRUE(Parsed->EffectiveModes().UseProductionFallback);
    }

    TEST(PreviewConfigurationContract, AppliesCommandLineConfigAndListenOverrides)
    {
        char Arg0[] = "PrismPreview";
        char Arg1[] = "--config";
        char Arg2[] = "custom-preview.json";
        char Arg3[] = "--listen";
        char Arg4[] = "127.0.0.1:9090";
        char *Args[] = {Arg0, Arg1, Arg2, Arg3, Arg4};

        const auto Parsed = PreviewBridge::ParseCommandLine(
            5, Args, std::filesystem::path("src/preview-configuration.json"));
        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->ConfigPath, std::filesystem::path("custom-preview.json"));
        ASSERT_TRUE(Parsed->ListenHost.has_value());
        ASSERT_TRUE(Parsed->ListenPort.has_value());
        EXPECT_EQ(*Parsed->ListenHost, "127.0.0.1");
        EXPECT_EQ(*Parsed->ListenPort, 9090U);

        auto Config = PreviewBridge::Configuration::Defaults();
        ASSERT_TRUE(PreviewBridge::ApplyCommandLineOverrides(Config, *Parsed));
        EXPECT_EQ(Config.Agent.addressable.host, "127.0.0.1");
        EXPECT_EQ(Config.Agent.addressable.port, 9090U);
    }

    TEST(PreviewConfigurationContract, ConvertsToProductionSettings)
    {
        auto Config = PreviewBridge::Configuration::Defaults();
        Config.Version = 7;
        Config.Agent.addressable.port = 8088;
        const auto Production = Config.ToProduction();

        EXPECT_EQ(Production.version, 7U);
        EXPECT_EQ(Production.instance.addressable.port, 8088U);
    }

} // namespace
