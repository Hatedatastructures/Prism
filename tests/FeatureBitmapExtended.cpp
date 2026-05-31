/**
 * @file FeatureBitmapExtended.cpp
 * @brief TLS 特征位图扩展测试 — build_bitmap/has_feature/has_all 分支覆盖
 */

#include <prism/memory.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/recognition/tls/features.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::recognition::tls::build_bitmap;
    using psm::recognition::tls::feature_bit;
    using psm::recognition::tls::has_all;
    using psm::recognition::tls::has_feature;
    using psm::protocol::tls::hello_features;

    void TestBitmapEmpty(TestRunner &runner)
    {
        hello_features features;
        auto bitmap = build_bitmap(features);
        runner.Check(bitmap == 0, "bitmap: empty features -> 0");
    }

    void TestBitmapSNI(TestRunner &runner)
    {
        hello_features features;
        features.server_name = "example.com";
        auto bitmap = build_bitmap(features);
        runner.Check(has_feature(bitmap, feature_bit::has_sni), "bitmap: has_sni set");
        runner.Check(!has_feature(bitmap, feature_bit::has_x25519), "bitmap: has_x25519 not set");
    }

    void TestBitmapX25519(TestRunner &runner)
    {
        hello_features features;
        features.has_x25519 = true;
        auto bitmap = build_bitmap(features);
        runner.Check(has_feature(bitmap, feature_bit::has_x25519), "bitmap: has_x25519 set");
    }

    void TestBitmapFullSession(TestRunner &runner)
    {
        hello_features features;
        features.session_id_len = 32;
        features.session_id.resize(32, 0xAA);
        auto bitmap = build_bitmap(features);
        runner.Check(has_feature(bitmap, feature_bit::full_session), "bitmap: full_session set");
        runner.Check(!has_feature(bitmap, feature_bit::nonstd_session), "bitmap: nonstd not set");
    }

    void TestBitmapNonstdSession(TestRunner &runner)
    {
        hello_features features;
        features.session_id_len = 16;
        features.session_id.resize(16, 0xBB);
        auto bitmap = build_bitmap(features);
        runner.Check(!has_feature(bitmap, feature_bit::full_session), "bitmap: not full_session");
        runner.Check(has_feature(bitmap, feature_bit::nonstd_session), "bitmap: nonstd_session set");
    }

    void TestBitmapNonstdSessionFromVector(TestRunner &runner)
    {
        // session_id_len=0 but session_id vector non-empty, non-32 -> nonstd
        hello_features features;
        features.session_id_len = 0;
        features.session_id.resize(16, 0xCC);
        auto bitmap = build_bitmap(features);
        runner.Check(has_feature(bitmap, feature_bit::nonstd_session), "bitmap: nonstd from vector");
    }

    void TestBitmapRealityMarker(TestRunner &runner)
    {
        hello_features features;
        features.session_id.resize(3);
        features.session_id[0] = 0x01;
        features.session_id[1] = 0x08;
        features.session_id[2] = 0x02;
        auto bitmap = build_bitmap(features);
        runner.Check(has_feature(bitmap, feature_bit::reality_marker), "bitmap: reality_marker set");
    }

    void TestBitmapRealityMarkerShortSID(TestRunner &runner)
    {
        hello_features features;
        features.session_id.resize(2);
        features.session_id[0] = 0x01;
        features.session_id[1] = 0x08;
        auto bitmap = build_bitmap(features);
        runner.Check(!has_feature(bitmap, feature_bit::reality_marker), "bitmap: short SID no marker");
    }

    void TestBitmapVersions(TestRunner &runner)
    {
        hello_features features;
        features.versions.push_back(0x0304);
        auto bitmap = build_bitmap(features);
        runner.Check(has_feature(bitmap, feature_bit::has_versions), "bitmap: has_versions set");
    }

    void TestBitmapECH(TestRunner &runner)
    {
        hello_features features;
        features.has_ech = true;
        auto bitmap = build_bitmap(features);
        runner.Check(has_feature(bitmap, feature_bit::has_ech), "bitmap: has_ech set");
    }

    void TestBitmapAllFlags(TestRunner &runner)
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
        runner.Check(has_feature(bitmap, feature_bit::has_sni), "bitmap: all has_sni");
        runner.Check(has_feature(bitmap, feature_bit::has_x25519), "bitmap: all has_x25519");
        runner.Check(has_feature(bitmap, feature_bit::full_session), "bitmap: all full_session");
        runner.Check(has_feature(bitmap, feature_bit::reality_marker), "bitmap: all reality");
        runner.Check(has_feature(bitmap, feature_bit::has_versions), "bitmap: all versions");
        runner.Check(has_feature(bitmap, feature_bit::has_ech), "bitmap: all ech");
    }

    void TestHasFeatureNegative(TestRunner &runner)
    {
        runner.Check(!has_feature(0, feature_bit::has_sni), "has_feature: 0 bitmap -> false");
        runner.Check(!has_feature(0, feature_bit::has_x25519), "has_feature: 0 bitmap x25519 -> false");
    }

    void TestHasAll(TestRunner &runner)
    {
        auto bits = feature_bit::has_sni | feature_bit::has_x25519;
        runner.Check(has_all(bits, bits), "has_all: exact match -> true");
        runner.Check(!has_all(0u, bits), "has_all: empty -> false");

        auto partial = static_cast<std::uint32_t>(feature_bit::has_sni);
        runner.Check(!has_all(partial, bits), "has_all: partial -> false");
        runner.Check(has_all(bits, partial), "has_all: superset -> true");
    }

    void TestBitwiseOr(TestRunner &runner)
    {
        auto a = feature_bit::has_sni;
        auto b = feature_bit::has_x25519;
        auto combined = a | b;
        runner.Check(has_feature(combined, feature_bit::has_sni), "or: has_sni present");
        runner.Check(has_feature(combined, feature_bit::has_x25519), "or: has_x25519 present");

        std::uint32_t base = 0;
        base |= feature_bit::has_ech;
        runner.Check(has_feature(base, feature_bit::has_ech), "or_eq: has_ech set");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("FeatureBitmapExtended");

    TestBitmapEmpty(runner);
    TestBitmapSNI(runner);
    TestBitmapX25519(runner);
    TestBitmapFullSession(runner);
    TestBitmapNonstdSession(runner);
    TestBitmapNonstdSessionFromVector(runner);
    TestBitmapRealityMarker(runner);
    TestBitmapRealityMarkerShortSID(runner);
    TestBitmapVersions(runner);
    TestBitmapECH(runner);
    TestBitmapAllFlags(runner);
    TestHasFeatureNegative(runner);
    TestHasAll(runner);
    TestBitwiseOr(runner);

    return runner.Summary();
}
