/**
 * @file WsSchemeDeep.cpp
 * @brief WebSocket scheme 属性测试
 */

#include <prism/handshake/ws/scheme.hpp>
#include <prism/settings/settings.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::handshake::ws::scheme;

    auto make_string(const std::string_view s) -> psm::memory::string
    {
        return psm::memory::string(s.data(), s.size());
    }
} // namespace

TEST(WsSchemeDeep, SchemeName)
{
    scheme s;
    EXPECT_EQ(s.name(), "ws");
}

TEST(WsSchemeDeep, SchemeTier)
{
    scheme s;
    EXPECT_EQ(s.tier(), 2) << "scheme: tier 2 (SNI)";
}

TEST(WsSchemeDeep, SchemeActiveEnabled)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.ws.server_names.push_back(make_string("example.com"));
    EXPECT_TRUE(s.active(cfg)) << "active when server_names configured";
}

TEST(WsSchemeDeep, SchemeActiveDisabled)
{
    scheme s;
    psm::settings cfg;
    EXPECT_FALSE(s.active(cfg)) << "inactive by default";
}

TEST(WsSchemeDeep, SchemeSnis)
{
    scheme s;
    psm::settings cfg;
    cfg.stealth.ws.server_names.push_back(make_string("a.com"));
    cfg.stealth.ws.server_names.push_back(make_string("b.com"));
    auto snis = s.snis(cfg);
    ASSERT_EQ(snis.size(), 2);
    EXPECT_EQ(snis[0], "a.com");
    EXPECT_EQ(snis[1], "b.com");
}
