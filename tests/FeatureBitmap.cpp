/**
 * @file FeatureBitmap.cpp
 * @brief TLS ClientHello 特征位图单元测试
 */

#include <prism/recognition/tls/features.hpp>
#include <prism/protocol/tls/types.hpp>
#include "common/TestRunner.hpp"

void TestFeatureBitmapBuild()
{
    psm::testing::TestRunner runner("FeatureBitmap::build_bitmap");

    // 测试空特征
    psm::protocol::tls::hello_features empty_features;
    auto bitmap = psm::recognition::tls::build_bitmap(empty_features);
    runner.Check(bitmap == 0, "Empty features should produce 0 bitmap");

    // 测试有 SNI
    psm::protocol::tls::hello_features sni_features;
    sni_features.server_name = "example.com";
    bitmap = psm::recognition::tls::build_bitmap(sni_features);
    runner.Check(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::has_sni), "Should have has_sni bit");

    // 测试有 X25519
    psm::protocol::tls::hello_features x25519_features;
    x25519_features.has_x25519 = true;
    bitmap = psm::recognition::tls::build_bitmap(x25519_features);
    runner.Check(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::has_x25519), "Should have has_x25519 bit");

    // 测试 session_id=32
    psm::protocol::tls::hello_features session_features;
    session_features.session_id_len = 32;
    session_features.session_id.resize(32);
    bitmap = psm::recognition::tls::build_bitmap(session_features);
    runner.Check(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::full_session), "Should have has_full_session_id bit");

    // 测试非标准 session_id
    psm::protocol::tls::hello_features non_std_features;
    non_std_features.session_id_len = 16;
    non_std_features.session_id.resize(16);
    bitmap = psm::recognition::tls::build_bitmap(non_std_features);
    runner.Check(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::nonstd_session), "Should have session_id_non_standard bit");

    runner.Summary();
}

void TestFeatureBitmapRealityMarker()
{
    psm::testing::TestRunner runner("FeatureBitmap::reality_marker");

    // 测试 Reality 独占标记 [01:08:02]
    psm::protocol::tls::hello_features reality_features;
    reality_features.session_id_len = 32;
    reality_features.session_id = {0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    auto bitmap = psm::recognition::tls::build_bitmap(reality_features);
    runner.Check(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::reality_marker),
                 "Should have reality_marker bit");
    runner.Check(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::full_session),
                 "Should also have full_session bit");

    // 测试非 Reality 标记
    psm::protocol::tls::hello_features non_reality_features;
    non_reality_features.session_id_len = 32;
    non_reality_features.session_id.resize(32);
    non_reality_features.session_id[0] = 0x00;

    bitmap = psm::recognition::tls::build_bitmap(non_reality_features);
    runner.Check(!psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::reality_marker),
                 "Should not have reality_marker bit");

    runner.Summary();
}

void TestFeatureBitmapHasAllFeatures()
{
    psm::testing::TestRunner runner("FeatureBitmap::has_all");

    // 构建包含多个特征的位图
    psm::protocol::tls::hello_features features;
    features.server_name = "example.com";
    features.has_x25519 = true;
    features.session_id_len = 32;
    features.session_id.resize(32);

    auto bitmap = psm::recognition::tls::build_bitmap(features);

    // 测试组合特征
    auto combined = psm::recognition::tls::feature_bit::has_sni | psm::recognition::tls::feature_bit::has_x25519 | psm::recognition::tls::feature_bit::full_session;
    runner.Check(psm::recognition::tls::has_all(bitmap, combined), "Should have all three features");

    // 测试部分匹配
    auto partial = psm::recognition::tls::feature_bit::has_sni | psm::recognition::tls::feature_bit::has_ech;
    runner.Check(!psm::recognition::tls::has_all(bitmap, partial), "Should not have ECH");

    runner.Summary();
}

int main()
{
    TestFeatureBitmapBuild();
    TestFeatureBitmapRealityMarker();
    TestFeatureBitmapHasAllFeatures();

    return 0;
}