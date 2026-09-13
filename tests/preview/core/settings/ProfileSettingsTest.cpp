/**
 * @file ProfileSettingsTest.cpp
 * @brief 识别策略配置解析测试（Task5 RED）
 */

#include <gtest/gtest.h>

#include <chrono>

#include <preview/Composition/Settings/Loader.hpp>

TEST(ProfileSettings, LegacyProtocolBuildsConfiguredCandidate)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(R"({"ListenPort":1080,"Protocol":"vless"})",
                                                     Config);

    ASSERT_TRUE(Error.Message.empty()) << Error.Message;
    EXPECT_EQ(Config.Recognition.Mode, Preview::Recognition::RecognitionMode::Configured);
    ASSERT_EQ(Config.Recognition.Candidates.size(), 1U);
    EXPECT_EQ(Config.Recognition.ConfiguredCandidate, 0U);
    EXPECT_EQ(Config.Recognition.Candidates.front().Protocol, "vless");
}

TEST(ProfileSettings, ParsesMixedCandidatesBudgetAndRoutes)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"MixedTrial","DefaultCandidate":7,"Budget":{"MaxProbeBytes":4096,"MaxCryptoTrials":4,"MaxRoutes":12,"MaxCandidateNameBytes":96,"MaxSchemeBytes":48,"TimeoutMs":250},"Candidates":[{"Id":2,"Name":"edge-vless","Protocol":"vless","Priority":3},{"Id":7,"Protocol":"ss2022","Fallback":true}],"Routes":[{"Pattern":"*.example.com","Candidate":2}]}})",
        Config);

    ASSERT_TRUE(Error.Message.empty()) << Error.Message;
    EXPECT_EQ(Config.Recognition.Mode, Preview::Recognition::RecognitionMode::MixedTrial);
    EXPECT_EQ(Config.Recognition.Budget.MaxProbeBytes, 4096U);
    EXPECT_EQ(Config.Recognition.Budget.MaxCryptoTrials, 4U);
    EXPECT_EQ(Config.Recognition.Budget.MaxRoutes, 12U);
    EXPECT_EQ(Config.Recognition.Budget.MaxCandidateNameBytes, 96U);
    EXPECT_EQ(Config.Recognition.Budget.MaxSchemeBytes, 48U);
    EXPECT_EQ(Config.Recognition.Budget.Timeout, std::chrono::milliseconds(250));
    EXPECT_EQ(Config.Recognition.DefaultCandidate, 7U);
    ASSERT_EQ(Config.Recognition.Candidates.size(), 2U);
    EXPECT_EQ(Config.Recognition.Candidates[0].Name, "edge-vless");
    ASSERT_EQ(Config.Recognition.Routes.size(), 1U);
    EXPECT_EQ(Config.Recognition.Routes[0].Candidate, 2U);
}

TEST(ProfileSettings, RejectsRecognitionMetadataBudgetOutOfRange)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"MixedTrial","Budget":{"MaxRoutes":4097},"Candidates":[{"Id":1,"Protocol":"http"}]}})",
        Config);

    EXPECT_EQ(Error.field, "Recognition.Budget.MaxRoutes");
    EXPECT_FALSE(Error.Message.empty());
}

TEST(ProfileSettings, ParsesDeterministicRouteMode)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"DeterministicRoute","Candidates":[{"Id":1,"Protocol":"http"},{"Id":2,"Protocol":"socks5"}],"Routes":[{"Pattern":"http.example","Candidate":1},{"Pattern":"socks.example","Candidate":2}]}})",
        Config);

    ASSERT_TRUE(Error.Message.empty()) << Error.Message;
    EXPECT_EQ(Config.Recognition.Mode, Preview::Recognition::RecognitionMode::Deterministic);
    ASSERT_EQ(Config.Recognition.Candidates.size(), 2U);
    ASSERT_EQ(Config.Recognition.Routes.size(), 2U);
}

TEST(ProfileSettings, ParsesCanonicalDeterministicMode)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"Deterministic","Candidates":[{"Id":1,"Protocol":"http"},{"Id":2,"Protocol":"socks5"}],"Routes":[{"Pattern":"http.example","Candidate":1},{"Pattern":"socks.example","Candidate":2}]}})",
        Config);

    ASSERT_TRUE(Error.Message.empty()) << Error.Message;
    EXPECT_EQ(Config.Recognition.Mode, Preview::Recognition::RecognitionMode::DeterministicRoute);
    ASSERT_EQ(Config.Recognition.Candidates.size(), 2U);
    ASSERT_EQ(Config.Recognition.Routes.size(), 2U);
}

TEST(ProfileSettings, UsesCanonicalRecognitionModeNames)
{
    EXPECT_EQ(Preview::Recognition::ToStringView(Preview::Recognition::RecognitionMode::Configured),
              "Configured");
    EXPECT_EQ(Preview::Recognition::ToStringView(Preview::Recognition::RecognitionMode::Deterministic),
              "Deterministic");
    EXPECT_EQ(Preview::Recognition::ToStringView(Preview::Recognition::RecognitionMode::DeterministicRoute),
              "Deterministic");
    EXPECT_EQ(Preview::Recognition::ToStringView(Preview::Recognition::RecognitionMode::MixedTrial),
              "MixedTrial");
}

TEST(ProfileSettings, RejectsDuplicateAndDanglingCandidates)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"MixedTrial","Candidates":[{"Id":1,"Protocol":"http"},{"Id":1,"Protocol":"trojan"}],"Routes":[{"Pattern":"edge.example","Candidate":99}]}})",
        Config);

    EXPECT_FALSE(Error.Message.empty());
}

TEST(ProfileSettings, RejectsFractionalNumericValues)
{
    Preview::Settings::ProxyConfig Config;
    EXPECT_FALSE(Preview::Settings::LoadConfig(R"({"ListenPort":1080.5})", Config).Message.empty());
    EXPECT_FALSE(Preview::Settings::LoadConfig(R"({"ListenPort":1080,"MaxConnections":4.5})", Config)
                     .Message.empty());
    EXPECT_FALSE(Preview::Settings::LoadConfig(R"({"ListenPort":1080,"IdleTimeoutMs":1.5})", Config)
                     .Message.empty());
    EXPECT_FALSE(Preview::Settings::LoadConfig(
                              R"({"ListenPort":1080,"Recognition":{"Mode":"Configured","Budget":{"MaxProbeBytes":4.5},"Candidates":[{"Id":1,"Protocol":"http"}]}})",
                              Config)
                     .Message.empty());
}

TEST(ProfileSettings, RejectsConfiguredCandidateInMixedTrial)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"MixedTrial","ConfiguredCandidate":2,"Candidates":[{"Id":2,"Protocol":"http"}]}})",
        Config);

    EXPECT_EQ(Error.field, "Recognition.ConfiguredCandidate");
    EXPECT_FALSE(Error.Message.empty());
}

TEST(ProfileSettings, AcceptsQuicRecognitionCandidates)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"MixedTrial","Candidates":[{"Id":20,"Protocol":"hysteria2"},{"Id":21,"Protocol":"tuic"}]}})",
        Config);

    ASSERT_TRUE(Error.Message.empty()) << Error.Message;
    ASSERT_EQ(Config.Recognition.Candidates.size(), 2U);
    EXPECT_EQ(Config.Recognition.Candidates[0].Protocol, "hysteria2");
    EXPECT_EQ(Config.Recognition.Candidates[1].Protocol, "tuic");
}

TEST(ProfileSettings, ParsesCarrierSchemeServerNamesAndAlpn)
{
    Preview::Settings::ProxyConfig Config;
    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"MixedTrial","Candidates":[{"Id":22,"Protocol":"vless","Scheme":"reality","ServerNames":["EXAMPLE.COM"],"Alpn":["h2","http/1.1"]},{"Id":23,"Name":"vless-native","Protocol":"vless","Scheme":"native"}]}})",
        Config);

    ASSERT_TRUE(Error.Message.empty()) << Error.Message;
    ASSERT_EQ(Config.Recognition.Candidates.size(), 2U);
    EXPECT_EQ(Config.Recognition.Candidates[0].Scheme, "reality");
    ASSERT_EQ(Config.Recognition.Candidates[0].ServerNames.size(), 1U);
    EXPECT_EQ(Config.Recognition.Candidates[0].ServerNames[0], "EXAMPLE.COM");
    ASSERT_EQ(Config.Recognition.Candidates[0].Alpn.size(), 2U);
    EXPECT_EQ(Config.Recognition.Candidates[0].Alpn[0], "h2");
    EXPECT_EQ(Config.Recognition.Candidates[0].Alpn[1], "http/1.1");
    EXPECT_EQ(Config.Recognition.Candidates[1].Scheme, "native");
}

TEST(ProfileSettings, NormalizesAndValidatesCarrierScheme)
{
    Preview::Settings::ProxyConfig Config;
    const auto Valid = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"Configured","Candidates":[{"Id":24,"Protocol":"vless","Scheme":"REALITY-v2"}]}})",
        Config);
    ASSERT_TRUE(Valid.Message.empty()) << Valid.Message;
    EXPECT_EQ(Config.Recognition.Candidates.front().Scheme, "reality-v2");

    const auto Invalid = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"Configured","Candidates":[{"Id":25,"Protocol":"vless","Scheme":"native tls"}]}})",
        Config);
    EXPECT_EQ(Invalid.field, "Recognition.Candidates[0].Scheme");
    EXPECT_FALSE(Invalid.Message.empty());
}

TEST(ProfileSettings, NormalizesProtocolNamesForRegistryLookup)
{
    Preview::Settings::ProxyConfig Config;

    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Protocol":"HTTP"})", Config);

    ASSERT_TRUE(Error.Message.empty()) << Error.Message;
    ASSERT_EQ(Config.Recognition.Candidates.size(), 1U);
    EXPECT_EQ(Config.Protocol, "http");
    EXPECT_EQ(Config.Recognition.Candidates.front().Protocol, "http");
}

TEST(ProfileSettings, RejectsTlsMetadataWithoutOuterScheme)
{
    Preview::Settings::ProxyConfig Config;

    const auto Error = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"Configured","Candidates":[{"Id":26,"Protocol":"http","Alpn":["h2"]}]}})",
        Config);

    EXPECT_EQ(Error.field, "Recognition.Candidates[0].Scheme");
    EXPECT_FALSE(Error.Message.empty());
}
