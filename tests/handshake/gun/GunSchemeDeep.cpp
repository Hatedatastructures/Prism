/**
 * @file GunSchemeDeep.cpp
 * @brief gRPC (gun) scheme 属性测试
 */

#include <prism/handshake/gun/scheme.hpp>
#include <prism/settings/settings.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::handshake::gun::scheme;
    namespace gun = psm::handshake::gun;

    auto make_string(const std::string_view s) -> psm::memory::string
    {
        return psm::memory::string(s.data(), s.size());
    }
} // namespace

TEST(GunSchemeDeep, SchemeName)
{
    scheme s;
    EXPECT_EQ(s.name(), "gun");
}

TEST(GunSchemeDeep, SchemeTier)
{
    scheme s;
    EXPECT_EQ(s.tier(), 2) << "scheme: tier 2 (SNI)";
}

TEST(GunSchemeDeep, SchemeActiveEnabled)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.gun.server_names.push_back(make_string("example.com"));
    EXPECT_TRUE(s.active(cfg)) << "scheme: active when server_names configured";
}

TEST(GunSchemeDeep, SchemeActiveDisabled)
{
    scheme s;
    psm::settings cfg;
    EXPECT_FALSE(s.active(cfg)) << "scheme: inactive by default";
}

TEST(GunSchemeDeep, SchemeSnis)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.gun.server_names.push_back(make_string("a.com"));
    cfg.stealth.gun.server_names.push_back(make_string("b.com"));
    auto snis = s.snis(cfg);
    ASSERT_EQ(snis.size(), 2);
    EXPECT_EQ(snis[0], "a.com");
    EXPECT_EQ(snis[1], "b.com");
}

TEST(GunSchemeDeep, SchemeGuess)
{
    scheme s;
    psm::settings cfg;
    auto result = s.guess(cfg);
    EXPECT_GT(result.score, 0);
}
