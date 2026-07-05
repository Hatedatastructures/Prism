/**
 * @file StealthFacadeSchemes.cpp
 * @brief Reality/Restls/ShadowTLS 方案纯接口测试
 */

#include <gtest/gtest.h>

#include <prism/config/config.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>
#include <prism/stealth/facade/restls/scheme.hpp>
#include <prism/stealth/facade/shadowtls/scheme.hpp>
#include <prism/stealth/scheme.hpp>

#include <string_view>

namespace
{
    // ─── Reality ──────────────────────────────────────

    TEST(StealthFacadeSchemes, RealityName)
    {
        psm::stealth::reality::scheme s;
        EXPECT_TRUE(s.name() == "reality") << "reality: name";
    }

    TEST(StealthFacadeSchemes, RealityTier)
    {
        psm::stealth::reality::scheme s;
        EXPECT_TRUE(s.tier() == 0) << "reality: tier=0";
    }

    TEST(StealthFacadeSchemes, RealityUnique)
    {
        psm::stealth::reality::scheme s;
        EXPECT_TRUE(s.unique()) << "reality: unique=true";
    }

    TEST(StealthFacadeSchemes, RealityCategory)
    {
        psm::stealth::reality::scheme s;
        EXPECT_TRUE(s.category() == psm::stealth::scheme_category::facade)
            << "reality: category=facade";
    }

    TEST(StealthFacadeSchemes, RealityActiveDisabled)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        EXPECT_TRUE(!s.active(cfg)) << "reality: active disabled by default";
    }

    TEST(StealthFacadeSchemes, RealityActivePartial)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        cfg.stealth.reality.dest = psm::memory::string("example.com:443");
        EXPECT_TRUE(!s.active(cfg)) << "reality: active disabled without key+snis";
    }

    TEST(StealthFacadeSchemes, RealityActiveEnabled)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        cfg.stealth.reality.dest = psm::memory::string("example.com:443");
        cfg.stealth.reality.private_key = psm::memory::string("base64key==");
        cfg.stealth.reality.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(s.active(cfg)) << "reality: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, RealitySnis)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        cfg.stealth.reality.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.reality.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.size() == 2) << "reality: snis count=2";
        EXPECT_TRUE(snis[0] == "a.example.com") << "reality: snis[0]";
        EXPECT_TRUE(snis[1] == "b.example.com") << "reality: snis[1]";
    }

    TEST(StealthFacadeSchemes, RealitySnisEmpty)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.empty()) << "reality: snis empty by default";
    }

    TEST(StealthFacadeSchemes, RealityGuess)
    {
        psm::stealth::reality::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        EXPECT_TRUE(result.score == 450) << "reality: guess score=450";
        EXPECT_TRUE(result.solo_flag == 0) << "reality: guess solo_flag=0";
    }

    // ─── Restls ──────────────────────────────────────

    TEST(StealthFacadeSchemes, RestlsName)
    {
        psm::stealth::restls::scheme s;
        EXPECT_TRUE(s.name() == "restls") << "restls: name";
    }

    TEST(StealthFacadeSchemes, RestlsTier)
    {
        psm::stealth::restls::scheme s;
        EXPECT_TRUE(s.tier() == 2) << "restls: tier=2";
    }

    TEST(StealthFacadeSchemes, RestlsUnique)
    {
        psm::stealth::restls::scheme s;
        EXPECT_TRUE(!s.unique()) << "restls: unique=false";
    }

    TEST(StealthFacadeSchemes, RestlsCategory)
    {
        psm::stealth::restls::scheme s;
        EXPECT_TRUE(s.category() == psm::stealth::scheme_category::facade)
            << "restls: category=facade";
    }

    TEST(StealthFacadeSchemes, RestlsActiveDisabled)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        EXPECT_TRUE(!s.active(cfg)) << "restls: active disabled by default";
    }

    TEST(StealthFacadeSchemes, RestlsActivePartial)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(!s.active(cfg)) << "restls: active disabled without host+password";
    }

    TEST(StealthFacadeSchemes, RestlsActiveEnabled)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("sni.example.com"));
        cfg.stealth.restls.host = psm::memory::string("backend:443");
        cfg.stealth.restls.password = psm::memory::string("secretpass");
        EXPECT_TRUE(s.active(cfg)) << "restls: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, RestlsSnis)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        cfg.stealth.restls.server_names.push_back(psm::memory::string("x.example.com"));
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.size() == 1) << "restls: snis count=1";
        EXPECT_TRUE(snis[0] == "x.example.com") << "restls: snis[0]";
    }

    TEST(StealthFacadeSchemes, RestlsSnisEmpty)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.empty()) << "restls: snis empty by default";
    }

    TEST(StealthFacadeSchemes, RestlsGuess)
    {
        psm::stealth::restls::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        EXPECT_TRUE(result.score == 100) << "restls: guess score=100";
        EXPECT_TRUE(result.solo_flag == 0) << "restls: guess solo_flag=0";
    }

    // ─── ShadowTLS ────────────────────────────────────

    TEST(StealthFacadeSchemes, ShadowtlsName)
    {
        psm::stealth::shadowtls::scheme s;
        EXPECT_TRUE(s.name() == "shadowtls") << "shadowtls: name";
    }

    TEST(StealthFacadeSchemes, ShadowtlsTier)
    {
        psm::stealth::shadowtls::scheme s;
        EXPECT_TRUE(s.tier() == 1) << "shadowtls: tier=1";
    }

    TEST(StealthFacadeSchemes, ShadowtlsUnique)
    {
        psm::stealth::shadowtls::scheme s;
        EXPECT_TRUE(!s.unique()) << "shadowtls: unique=false";
    }

    TEST(StealthFacadeSchemes, ShadowtlsCategory)
    {
        psm::stealth::shadowtls::scheme s;
        EXPECT_TRUE(s.category() == psm::stealth::scheme_category::facade)
            << "shadowtls: category=facade";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV3Disabled)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        EXPECT_TRUE(!s.active(cfg)) << "shadowtls v3: active disabled by default";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV3Enabled)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 3;
        psm::stealth::shadowtls::user u;
        u.name = psm::memory::string("user1");
        u.password = psm::memory::string("pass1");
        cfg.stealth.shadowtls.users.push_back(std::move(u));
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(s.active(cfg)) << "shadowtls v3: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV3NoUsers)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 3;
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(!s.active(cfg)) << "shadowtls v3: active disabled without users";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV2Enabled)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 2;
        cfg.stealth.shadowtls.password = psm::memory::string("v2pass");
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(s.active(cfg)) << "shadowtls v2: active enabled with all fields";
    }

    TEST(StealthFacadeSchemes, ShadowtlsActiveV2NoPassword)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.version = 2;
        cfg.stealth.shadowtls.handshake_dest = psm::memory::string("backend:443");
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("sni.example.com"));
        EXPECT_TRUE(!s.active(cfg)) << "shadowtls v2: active disabled without password";
    }

    TEST(StealthFacadeSchemes, ShadowtlsSnis)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.shadowtls.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.size() == 2) << "shadowtls: snis count=2";
        EXPECT_TRUE(snis[0] == "a.example.com") << "shadowtls: snis[0]";
    }

    TEST(StealthFacadeSchemes, ShadowtlsSnisEmpty)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.empty()) << "shadowtls: snis empty by default";
    }

    TEST(StealthFacadeSchemes, ShadowtlsGuess)
    {
        psm::stealth::shadowtls::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        EXPECT_TRUE(result.score == 100) << "shadowtls: guess score=100";
        EXPECT_TRUE(result.solo_flag == 0) << "shadowtls: guess solo_flag=0";
    }

} // namespace
