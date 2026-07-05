/**
 * @file AnytlsSchemeExtended.cpp
 * @brief AnyTLS 方案扩展接口测试 — verify 分支覆盖
 */

#include <gtest/gtest.h>

#include <prism/config/config.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/stealth/stack/anytls/scheme.hpp>
#include <prism/stealth/scheme.hpp>

#include <cstddef>
#include <span>

namespace
{
    TEST(AnytlsSchemeExtended, AnytlsName)
    {
        psm::stealth::anytls::scheme s;
        EXPECT_TRUE(s.name() == "anytls") << "anytls: name";
    }

    TEST(AnytlsSchemeExtended, AnytlsTier)
    {
        psm::stealth::anytls::scheme s;
        EXPECT_TRUE(s.tier() == 2) << "anytls: tier=2";
    }

    TEST(AnytlsSchemeExtended, AnytlsUnique)
    {
        psm::stealth::anytls::scheme s;
        EXPECT_TRUE(!s.unique()) << "anytls: unique=false";
    }

    TEST(AnytlsSchemeExtended, AnytlsCategory)
    {
        psm::stealth::anytls::scheme s;
        EXPECT_TRUE(s.category() == psm::stealth::scheme_category::stack)
            << "anytls: category=stack";
    }

    TEST(AnytlsSchemeExtended, AnytlsActiveDisabled)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        EXPECT_TRUE(!s.active(cfg)) << "anytls: active disabled by default";
    }

    TEST(AnytlsSchemeExtended, AnytlsActiveEnabled)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        cfg.stealth.anytls.server_names.push_back(psm::memory::string("sni.example.com"));
        cfg.stealth.anytls.certificate = psm::memory::string("/path/cert.pem");
        cfg.stealth.anytls.private_key = psm::memory::string("/path/key.pem");
        psm::stealth::anytls::user u;
        u.username = psm::memory::string("admin");
        u.password = psm::memory::string("secret");
        cfg.stealth.anytls.users.push_back(std::move(u));
        EXPECT_TRUE(s.active(cfg)) << "anytls: active enabled";
    }

    TEST(AnytlsSchemeExtended, AnytlsSnis)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        cfg.stealth.anytls.server_names.push_back(psm::memory::string("a.example.com"));
        cfg.stealth.anytls.server_names.push_back(psm::memory::string("b.example.com"));
        auto snis = s.snis(cfg);
        EXPECT_TRUE(snis.size() == 2) << "anytls: snis count=2";
    }

    TEST(AnytlsSchemeExtended, AnytlsGuess)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        auto result = s.guess(cfg);
        EXPECT_TRUE(result.score == 100) << "anytls: guess score=100";
        EXPECT_TRUE(result.solo_flag == 0) << "anytls: guess solo_flag=0";
    }

    TEST(AnytlsSchemeExtended, AnytlsVerifyNoEch)
    {
        psm::stealth::anytls::scheme s;
        psm::config cfg;
        psm::protocol::tls::hello_features features{};
        std::array<std::byte, 64> raw{};
        auto result = s.verify(features, raw, cfg);
        EXPECT_TRUE(result.score == 0) << "anytls: verify no ech -> score=0";
    }
} // namespace
