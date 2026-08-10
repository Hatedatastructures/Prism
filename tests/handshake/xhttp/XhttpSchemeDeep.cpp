/**
 * @file XhttpSchemeDeep.cpp
 * @brief XHTTP scheme 属性测试
 */

#include <prism/handshake/xhttp/scheme.hpp>
#include <prism/settings/settings.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::handshake::xhttp::scheme;

    auto make_string(const std::string_view s) -> psm::memory::string
    {
        return psm::memory::string(s.data(), s.size());
    }
}

TEST(XhttpSchemeDeep, SchemeName)
{
    scheme s;
    EXPECT_EQ(s.name(), "xhttp");
}

TEST(XhttpSchemeDeep, SchemeTier)
{
    scheme s;
    EXPECT_EQ(s.tier(), 2) << "scheme: tier 2 (SNI)";
}

TEST(XhttpSchemeDeep, SchemeActiveEnabled)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.xhttp.server_names.push_back(make_string("example.com"));
    EXPECT_TRUE(s.active(cfg)) << "active when server_names configured";
}

TEST(XhttpSchemeDeep, SchemeActiveDisabled)
{
    scheme s;
    psm::settings cfg;
    EXPECT_FALSE(s.active(cfg)) << "inactive by default";
}

TEST(XhttpSchemeDeep, SchemeSnis)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.xhttp.server_names.push_back(make_string("a.com"));
    auto snis = s.snis(cfg);
    ASSERT_EQ(snis.size(), 1);
    EXPECT_EQ(snis[0], "a.com");
}

TEST(XhttpSchemeDeep, SchemeGuess)
{
    scheme s;
    psm::settings cfg;
    auto result = s.guess(cfg);
    EXPECT_GT(result.score, 0);
}
