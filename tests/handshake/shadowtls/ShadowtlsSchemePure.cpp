/**
 * @file ShadowtlsSchemePure.cpp
 * @brief ShadowTLS scheme sniff/verify 纯函数测试
 * @details 测试 sniff 和 verify 方法的所有分支路径
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/settings/settings.hpp>
#include <prism/handshake/facade/shadowtls/scheme.hpp>
#include <prism/handshake/recognition/tls/features.hpp>
#include <prism/protocol/tls/types.hpp>

namespace
{
    TEST(ShadowtlsSchemePure, SniffNonstdSession)
    {
        psm::handshake::shadowtls::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(psm::recognition::tls::feature_bit::nonstd_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(result.hit) << "sniff: nonstd_session hit";
        EXPECT_TRUE(!result.solo) << "sniff: nonstd_session not solo";
        EXPECT_TRUE(result.hint == 150) << "sniff: nonstd_session hint=150";
    }

    TEST(ShadowtlsSchemePure, SniffMiss)
    {
        psm::handshake::shadowtls::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(psm::recognition::tls::feature_bit::has_x25519);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(!result.hit) << "sniff: x25519 only -> miss";
    }

    TEST(ShadowtlsSchemePure, SniffEmpty)
    {
        psm::handshake::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(0, features);
        EXPECT_TRUE(!result.hit) << "sniff: empty bitmap -> miss";
    }

    TEST(ShadowtlsSchemePure, VerifyTooShort)
    {
        psm::handshake::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 32;
        std::array<std::byte, 10> small{};
        psm::settings cfg;
        auto result = sch.verify(features, small, cfg);
        EXPECT_TRUE(result.score == 50) << "verify: too short -> score=50";
        EXPECT_TRUE(result.solo_flag == 0) << "verify: too short -> no solo";
    }

    TEST(ShadowtlsSchemePure, VerifyWrongSessionIdLen)
    {
        psm::handshake::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 16;
        std::array<std::byte, 100> buf{};
        psm::settings cfg;
        auto result = sch.verify(features, buf, cfg);
        EXPECT_TRUE(result.score == 50) << "verify: wrong session_id_len -> score=50";
    }

    TEST(ShadowtlsSchemePure, VerifyV3NoUsers)
    {
        psm::handshake::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 32;
        std::array<std::byte, 100> buf{};
        psm::settings cfg;
        cfg.stealth.shadowtls.version = 3;
        auto result = sch.verify(features, buf, cfg);
        EXPECT_TRUE(result.score == 50) << "verify: v3 no users -> score=50";
    }

    TEST(ShadowtlsSchemePure, VerifyV2NoPassword)
    {
        psm::handshake::shadowtls::scheme sch;
        psm::protocol::tls::hello_features features;
        features.session_id_len = 32;
        std::array<std::byte, 100> buf{};
        psm::settings cfg;
        cfg.stealth.shadowtls.version = 2;
        auto result = sch.verify(features, buf, cfg);
        EXPECT_TRUE(result.score == 50) << "verify: v2 no password -> score=50";
    }

} // namespace
