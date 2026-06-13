/**
 * @file TrustTunnelPure.cpp
 * @brief TrustTunnel 方案纯函数与元数据接口测试
 */

#include <gtest/gtest.h>

#include <prism/config/config.hpp>
#include <prism/core/core.hpp>
#include <prism/stealth/stack/trusttunnel/scheme.hpp>
#include <prism/stealth/scheme.hpp>

#include <string>
#include <string_view>

namespace
{
    TEST(TrustTunnelPure, Name)
    {
        psm::stealth::trusttunnel::scheme s;
        EXPECT_TRUE(s.name() == "trusttunnel") << "name: trusttunnel";
    }

    TEST(TrustTunnelPure, Tier)
    {
        psm::stealth::trusttunnel::scheme s;
        EXPECT_TRUE(s.tier() == 2) << "tier: 2";
    }

    TEST(TrustTunnelPure, Unique)
    {
        psm::stealth::trusttunnel::scheme s;
        EXPECT_TRUE(!s.unique()) << "unique: false";
    }

    TEST(TrustTunnelPure, Category)
    {
        psm::stealth::trusttunnel::scheme s;
        EXPECT_TRUE(s.category() == psm::stealth::scheme_category::stack)
            << "category: stack";
    }

    TEST(TrustTunnelPure, Guess)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        EXPECT_TRUE(result.score == 100) << "guess: score=100";
        EXPECT_TRUE(result.solo_flag == 0) << "guess: solo_flag=0";
    }

    TEST(TrustTunnelPure, ActiveDisabled)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        // 默认配置：无 server_names/certificate/private_key/users -> enabled() = false
        EXPECT_TRUE(!s.active(cfg)) << "active: disabled by default";
    }

    TEST(TrustTunnelPure, ActiveEnabled)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        // 设置所有必需字段
        cfg.stealth.trusttunnel.server_names.push_back(psm::memory::string("example.com"));
        cfg.stealth.trusttunnel.certificate = psm::memory::string("/path/to/cert.pem");
        cfg.stealth.trusttunnel.private_key = psm::memory::string("/path/to/key.pem");
        psm::stealth::trusttunnel::user u;
        u.username = psm::memory::string("admin");
        u.password = psm::memory::string("secret");
        cfg.stealth.trusttunnel.users.push_back(std::move(u));

        EXPECT_TRUE(s.active(cfg)) << "active: enabled with all fields";
    }

    TEST(TrustTunnelPure, Snis)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        cfg.stealth.trusttunnel.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.trusttunnel.server_names.push_back(psm::memory::string("b.example.com"));

        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.size() == 2) << "snis: 2 entries";
        EXPECT_TRUE(snis[0] == "a.example.com") << "snis: first";
        EXPECT_TRUE(snis[1] == "b.example.com") << "snis: second";
    }

    TEST(TrustTunnelPure, SnisEmpty)
    {
        psm::stealth::trusttunnel::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.empty()) << "snis: empty by default";
    }

} // namespace
