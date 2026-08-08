/**
 * @file StealthFacadeSchemes.cpp
 * @brief Reality/Restls/ShadowTLS 方案纯接口测试
 */

#include <gtest/gtest.h>

#include <prism/settings/settings.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/handshake/reality/scheme.hpp>
#include <prism/handshake/restls/scheme.hpp>
#include <prism/handshake/shadowtls/scheme.hpp>
#include <prism/handshake/scheme.hpp>

#include <string_view>

namespace
{
    // ─── Reality ──────────────────────────────────────

    TEST(StealthFacadeSchemes, RealityName)
    {
        psm::handshake::reality::scheme s;
        EXPECT_EQ(s.name(), "reality") << "reality: name";
    }

    TEST(StealthFacadeSchemes, RealityTier)
    {
        psm::handshake::reality::scheme s;
        EXPECT_EQ(s.tier(), 0) << "reality: tier=0";
    }

    TEST(StealthFacadeSchemes, RealityUnique)
    {
        psm::handshake::reality::scheme s;
        EXPECT_TRUE(s.unique()) << "reality: unique=true";
    }

    TEST(StealthFacadeSchemes, RealityCategory)
    {
        psm::handshake::reality::scheme s;
        EXPECT_EQ(s.category(), psm::handshake::scheme_category::facade)
            << "reality: category=facade";
    }

    TEST(StealthFacadeSchemes, RealityActiveDisabled)
    {
        psm::handshake::reality::scheme s;
        psm::settings cfg;
        EXPECT_TRUE(!s.active(cfg)) << "reality: active disabled by default";
    }

    TEST(StealthFacadeSchemes, RealityActivePartial)
    {
        psm::handshake::reality::scheme s;
        psm::settings cfg;
        cfg.stealth.reality.dest = psm::memory::string("example.com:443");
        EXPECT_TRUE(!s.active(cfg)) << "reality: active disabled without key+snis";
    }

    TEST(StealthFacadeSchemes, RealityActiveEnabled)
    {
        psm::handshake::reality::scheme s;
        psm::settings cfg;
        cfg.stealth.reality.dest = psm::memory::string("example.com:443");
        cfg.stealth.reality.private_key = psm::memory::string("base64key==");
        cfg.stealth.reality.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(s.active(cfg)) << "reality: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, RealitySnis)
    {
        psm::handshake::reality::scheme s;
        psm::settings cfg;
        cfg.stealth.reality.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.reality.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        EXPECT_EQ(snis.size(), 2) << "reality: snis count=2";
        EXPECT_EQ(snis[0], "a.example.com") << "reality: snis[0]";
        EXPECT_EQ(snis[1], "b.example.com") << "reality: snis[1]";
    }

    TEST(StealthFacadeSchemes, RealitySnisEmpty)
    {
        psm::handshake::reality::scheme s;
        psm::settings cfg;
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.empty()) << "reality: snis empty by default";
    }

    TEST(StealthFacadeSchemes, RealityGuess)
    {
        psm::handshake::reality::scheme s;
        psm::settings cfg;
        auto result = s.guess(cfg);
        EXPECT_EQ(result.score, 450) << "reality: guess score=450";
        EXPECT_EQ(result.solo_flag, 0) << "reality: guess solo_flag=0";
    }

    // ─── Restls ──────────────────────────────────────

    TEST(StealthFacadeSchemes, RestlsName)
    {
        psm::handshake::restls::scheme s;
        EXPECT_EQ(s.name(), "restls") << "restls: name";
    }

    TEST(StealthFacadeSchemes, RestlsTier)
    {
        psm::handshake::restls::scheme s;
        EXPECT_EQ(s.tier(), 2) << "restls: tier=2";
    }

    TEST(StealthFacadeSchemes, RestlsUnique)
    {
        psm::handshake::restls::scheme s;
        EXPECT_TRUE(!s.unique()) << "restls: unique=false";
    }

    TEST(StealthFacadeSchemes, RestlsCategory)
    {
        psm::handshake::restls::scheme s;
        EXPECT_EQ(s.category(), psm::handshake::scheme_category::facade)
            << "restls: category=facade";
    }

    TEST(StealthFacadeSchemes, RestlsActiveDisabled)
    {
        psm::handshake::restls::scheme s;
        psm::settings cfg;
        EXPECT_TRUE(!s.active(cfg)) << "restls: active disabled by default";
    }

    TEST(StealthFacadeSchemes, RestlsActivePartial)
    {
        psm::handshake::restls::scheme s;
        psm::settings cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(!s.active(cfg)) << "restls: active disabled without host+password";
    }

    TEST(StealthFacadeSchemes, RestlsActiveEnabled)
    {
        psm::handshake::restls::scheme s;
        psm::settings cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("sni.example.com"));
        cfg.stealth.restls.host = psm::memory::string("backend:443");
        cfg.stealth.restls.password = psm::memory::string("secretpass");
        EXPECT_TRUE(s.active(cfg)) << "restls: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, RestlsSnis)
    {
        psm::handshake::restls::scheme s;
        psm::settings cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("x.example.com"));
        auto snis = s.snis(cfg);
        EXPECT_EQ(snis.size(), 1) << "restls: snis count=1";
        EXPECT_EQ(snis[0], "x.example.com") << "restls: snis[0]";
    }

    TEST(StealthFacadeSchemes, RestlsSnisEmpty)
    {
        psm::handshake::restls::scheme s;
        psm::settings cfg;
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.empty()) << "restls: snis empty by default";
    }

    TEST(StealthFacadeSchemes, RestlsGuess)
    {
        psm::handshake::restls::scheme s;
        psm::settings cfg;
        auto result = s.guess(cfg);
        EXPECT_EQ(result.score, 100) << "restls: guess score=100";
        EXPECT_EQ(result.solo_flag, 0) << "restls: guess solo_flag=0";
    }

    // ─── ShadowTLS ────────────────────────────────────

    TEST(StealthFacadeSchemes, ShadowtlsName)
    {
        psm::handshake::shadowtls::scheme s;
        EXPECT_EQ(s.name(), "shadowtls") << "shadowtls: name";
    }

    TEST(StealthFacadeSchemes, ShadowtlsTier)
    {
        psm::handshake::shadowtls::scheme s;
        EXPECT_EQ(s.tier(), 1) << "shadowtls: tier=1";
    }

    TEST(StealthFacadeSchemes, ShadowtlsUnique)
    {
        psm::handshake::shadowtls::scheme s;
        EXPECT_TRUE(!s.unique()) << "shadowtls: unique=false";
    }

    TEST(StealthFacadeSchemes, ShadowtlsCategory)
    {
        psm::handshake::shadowtls::scheme s;
        EXPECT_EQ(s.category(), psm::handshake::scheme_category::facade)
            << "shadowtls: category=facade";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV3Disabled)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        EXPECT_TRUE(!s.active(cfg)) << "shadowtls v3: active disabled by default";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV3Enabled)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        cfg.stealth.shadowtls.version = 3;
        psm::handshake::shadowtls::user u;
        u.name = psm::memory::string("user1");
        u.password = psm::memory::string("pass1");
        cfg.stealth.shadowtls.users.push_back(std::move(u));
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(s.active(cfg)) << "shadowtls v3: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV3NoUsers)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        cfg.stealth.shadowtls.version = 3;
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(!s.active(cfg)) << "shadowtls v3: active disabled without users";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV2Enabled)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        cfg.stealth.shadowtls.version = 2;
        cfg.stealth.shadowtls.password = psm::memory::string("v2pass");
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(s.active(cfg)) << "shadowtls v2: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV2NoPassword)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        cfg.stealth.shadowtls.version = 2;
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(!s.active(cfg)) << "shadowtls v2: active disabled without password";
    }

    TEST(StealthFacadeSchemes, ShadowtlsSnis)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        EXPECT_EQ(snis.size(), 2) << "shadowtls: snis count=2";
        EXPECT_EQ(snis[0], "a.example.com") << "shadowtls: snis[0]";
    }

    TEST(StealthFacadeSchemes, ShadowtlsSnisEmpty)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.empty()) << "shadowtls: snis empty by default";
    }

    TEST(StealthFacadeSchemes, ShadowtlsGuess)
    {
        psm::handshake::shadowtls::scheme s;
        psm::settings cfg;
        auto result = s.guess(cfg);
        EXPECT_EQ(result.score, 100) << "shadowtls: guess score=100";
        EXPECT_EQ(result.solo_flag, 0) << "shadowtls: guess solo_flag=0";
    }

} // namespace
