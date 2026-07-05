/**
 * @file FeatureBitmapExtended.cpp
 * @brief TLS 特征位图扩展测试 — build_bitmap/has_feature/has_all 分支覆盖
 */

#include <prism/foundation/foundation.hpp>
#include <prism/proto/protocol/tls/types.hpp>
#include <prism/stealth/recognition/tls/features.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::recognition::tls::build_bitmap;
    using psm::recognition::tls::feature_bit;
    using psm::recognition::tls::has_all;
    using psm::recognition::tls::has_feature;
    using psm::protocol::tls::hello_features;

    TEST(FeatureBitmapExtended, BitmapEmpty)
    {
        hello_features features;
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(bitmap == 0) << "bitmap: empty features -> 0";
    }

    TEST(FeatureBitmapExtended, BitmapSNI)
    {
        hello_features features;
        features.server_name = "example.com";
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_sni)) << "bitmap: has_sni set";
        EXPECT_TRUE(!has_feature(bitmap, feature_bit::has_x25519)) << "bitmap: has_x25519 not set";
    }

    TEST(FeatureBitmapExtended, BitmapX25519)
    {
        hello_features features;
        features.has_x25519 = true;
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_x25519)) << "bitmap: has_x25519 set";
    }

    TEST(FeatureBitmapExtended, BitmapFullSession)
    {
        hello_features features;
        features.session_id_len = 32;
        features.session_id.resize(32, 0xAA);
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::full_session)) << "bitmap: full_session set";
        EXPECT_TRUE(!has_feature(bitmap, feature_bit::nonstd_session)) << "bitmap: nonstd not set";
    }

    TEST(FeatureBitmapExtended, BitmapNonstdSession)
    {
        hello_features features;
        features.session_id_len = 16;
        features.session_id.resize(16, 0xBB);
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(!has_feature(bitmap, feature_bit::full_session)) << "bitmap: not full_session";
        EXPECT_TRUE(has_feature(bitmap, feature_bit::nonstd_session)) << "bitmap: nonstd_session set";
    }

    TEST(FeatureBitmapExtended, BitmapNonstdSessionFromVector)
    {
        // session_id_len=0 but session_id vector non-empty, non-32 -> nonstd
        hello_features features;
        features.session_id_len = 0;
        features.session_id.resize(16, 0xCC);
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::nonstd_session)) << "bitmap: nonstd from vector";
    }

    TEST(FeatureBitmapExtended, BitmapRealityMarker)
    {
        hello_features features;
        features.session_id.resize(3);
        features.session_id[0] = 0x01;
        features.session_id[1] = 0x08;
        features.session_id[2] = 0x02;
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::reality_marker)) << "bitmap: reality_marker set";
    }

    TEST(FeatureBitmapExtended, BitmapRealityMarkerShortSID)
    {
        hello_features features;
        features.session_id.resize(2);
        features.session_id[0] = 0x01;
        features.session_id[1] = 0x08;
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(!has_feature(bitmap, feature_bit::reality_marker)) << "bitmap: short SID no marker";
    }

    TEST(FeatureBitmapExtended, BitmapVersions)
    {
        hello_features features;
        features.versions.push_back(0x0304);
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_versions)) << "bitmap: has_versions set";
    }

    TEST(FeatureBitmapExtended, BitmapECH)
    {
        hello_features features;
        features.has_ech = true;
        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_ech)) << "bitmap: has_ech set";
    }

    TEST(FeatureBitmapExtended, BitmapAllFlags)
    {
        hello_features features;
        features.server_name = "full.test";
        features.has_x25519 = true;
        features.session_id_len = 32;
        features.session_id.resize(32, 0xDD);
        features.session_id[0] = 0x01;
        features.session_id[1] = 0x08;
        features.session_id[2] = 0x02;
        features.versions.push_back(0x0303);
        features.versions.push_back(0x0304);
        features.has_ech = true;

        auto bitmap = build_bitmap(features);
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_sni)) << "bitmap: all has_sni";
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_x25519)) << "bitmap: all has_x25519";
        EXPECT_TRUE(has_feature(bitmap, feature_bit::full_session)) << "bitmap: all full_session";
        EXPECT_TRUE(has_feature(bitmap, feature_bit::reality_marker)) << "bitmap: all reality";
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_versions)) << "bitmap: all versions";
        EXPECT_TRUE(has_feature(bitmap, feature_bit::has_ech)) << "bitmap: all ech";
    }

    TEST(FeatureBitmapExtended, HasFeatureNegative)
    {
        EXPECT_TRUE(!has_feature(0, feature_bit::has_sni)) << "has_feature: 0 bitmap -> false";
        EXPECT_TRUE(!has_feature(0, feature_bit::has_x25519)) << "has_feature: 0 bitmap x25519 -> false";
    }

    TEST(FeatureBitmapExtended, HasAll)
    {
        auto bits = feature_bit::has_sni | feature_bit::has_x25519;
        EXPECT_TRUE(has_all(bits, bits)) << "has_all: exact match -> true";
        EXPECT_TRUE(!has_all(0u, bits)) << "has_all: empty -> false";

        auto partial = static_cast<std::uint32_t>(feature_bit::has_sni);
        EXPECT_TRUE(!has_all(partial, bits)) << "has_all: partial -> false";
        EXPECT_TRUE(has_all(bits, partial)) << "has_all: superset -> true";
    }

    TEST(FeatureBitmapExtended, BitwiseOr)
    {
        auto a = feature_bit::has_sni;
        auto b = feature_bit::has_x25519;
        auto combined = a | b;
        EXPECT_TRUE(has_feature(combined, feature_bit::has_sni)) << "or: has_sni present";
        EXPECT_TRUE(has_feature(combined, feature_bit::has_x25519)) << "or: has_x25519 present";

        std::uint32_t base = 0;
        base |= feature_bit::has_ech;
        EXPECT_TRUE(has_feature(base, feature_bit::has_ech)) << "or_eq: has_ech set";
    }
} // namespace
