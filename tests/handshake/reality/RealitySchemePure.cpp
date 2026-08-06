/**
 * @file RealitySchemePure.cpp
 * @brief Reality scheme sniff() 全分支测试
 * @details 覆盖 sniff() 的 7 条分支路径
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/handshake/facade/reality/scheme.hpp>
#include <prism/handshake/recognition/tls/features.hpp>
#include <prism/protocol/tls/types.hpp>

namespace
{
    namespace rfeat = psm::recognition::tls;
    using fb = rfeat::feature_bit;

    TEST(RealitySchemePure, SniffRealityMarker)
    {
        psm::handshake::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::reality_marker);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(result.hit) << "reality marker: hit";
        EXPECT_TRUE(result.solo) << "reality marker: solo";
        EXPECT_TRUE(result.hint == 950) << "reality marker: hint=950";
    }

    TEST(RealitySchemePure, SniffX25519FullSession)
    {
        psm::handshake::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_x25519 | fb::full_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(result.hit) << "x25519+full: hit";
        EXPECT_TRUE(!result.solo) << "x25519+full: not solo";
        EXPECT_TRUE(result.hint == 450) << "x25519+full: hint=450";
    }

    TEST(RealitySchemePure, SniffX25519NonstdSession)
    {
        psm::handshake::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_x25519 | fb::nonstd_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(result.hit) << "x25519+nonstd: hit";
        EXPECT_TRUE(!result.solo) << "x25519+nonstd: not solo";
        EXPECT_TRUE(result.hint == 400) << "x25519+nonstd: hint=400";
    }

    TEST(RealitySchemePure, SniffX25519Only)
    {
        psm::handshake::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_x25519);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(result.hit) << "x25519 only: hit";
        EXPECT_TRUE(!result.solo) << "x25519 only: not solo";
        EXPECT_TRUE(result.hint == 200) << "x25519 only: hint=200";
    }

    TEST(RealitySchemePure, SniffSniFullSession)
    {
        psm::handshake::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_sni | fb::full_session);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(result.hit) << "sni+full: hit";
        EXPECT_TRUE(!result.solo) << "sni+full: not solo";
        EXPECT_TRUE(result.hint == 100) << "sni+full: hint=100";
    }

    TEST(RealitySchemePure, SniffSniOnly)
    {
        psm::handshake::reality::scheme sch;
        std::uint32_t bitmap = static_cast<std::uint32_t>(fb::has_sni);
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(bitmap, features);
        EXPECT_TRUE(result.hit) << "sni only: hit";
        EXPECT_TRUE(!result.solo) << "sni only: not solo";
        EXPECT_TRUE(result.hint == 100) << "sni only: hint=100";
    }

    TEST(RealitySchemePure, SniffMiss)
    {
        psm::handshake::reality::scheme sch;
        psm::protocol::tls::hello_features features;
        auto result = sch.sniff(0, features);
        EXPECT_TRUE(!result.hit) << "empty: miss";
    }

} // namespace
