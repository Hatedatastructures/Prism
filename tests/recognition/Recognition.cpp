/**
 * @file Recognition.cpp
 * @brief Recognition 模块单元测试（新接口）
 * @details 测试 recognition 模块的核心功能，包括：
 * 1. probe::detect() 外层协议探测
 * 2. SchemeRouteTable SNI 路由
 * 3. FeatureBitmap 特征位图构建
 * 4. Reality sniff 独占标记检测
 * 5. scheme_registry 注册与查询
 * 6. 结构体默认值验证
 */

#include <prism/recognition/probe/probe.hpp>
#include <prism/recognition/routes.hpp>
#include <prism/recognition/tls/features.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/config.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <string>

namespace probe = psm::recognition::probe;
using psm::protocol::tls::hello_features;
using psm::recognition::tls::feature_bit;

namespace
{
    /**
     * @brief 构建一个启用了 reality 的配置对象
     */
    auto make_reality_config() -> psm::config
    {
        psm::config cfg;
        cfg.stealth.reality.dest = "example.com:443";
        cfg.stealth.reality.private_key = "dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVzdHRlc3Q=";
        cfg.stealth.reality.server_names.push_back("example.com");
        return cfg;
    }

    /**
     * @brief 构建多协议测试配置
     */
    auto make_multi_scheme_config() -> psm::config
    {
        psm::config cfg;

        // Reality 配置
        cfg.stealth.reality.server_names.push_back("reality.example.com");
        cfg.stealth.reality.dest = "www.microsoft.com:443";
        cfg.stealth.reality.private_key = "test_key_base64";

        // ShadowTLS 配置
        cfg.stealth.shadowtls.server_names.push_back("shadowtls.example.com");
        cfg.stealth.shadowtls.handshake_dest = "www.microsoft.com:443";
        cfg.stealth.shadowtls.users.push_back({"user1", "password1"});

        // Restls 配置
        cfg.stealth.restls.server_names.push_back("restls.example.com");
        cfg.stealth.restls.host = "www.microsoft.com:443";
        cfg.stealth.restls.password = "restls_password";

        // AnyTLS 配置
        cfg.stealth.anytls.server_names.push_back("anytls.example.com");
        cfg.stealth.anytls.certificate = "cert.pem";
        cfg.stealth.anytls.private_key = "key.pem";
        cfg.stealth.anytls.users.push_back({"user1", "password1"});

        // TrustTunnel 配置
        cfg.stealth.trusttunnel.server_names.push_back("trusttunnel.example.com");
        cfg.stealth.trusttunnel.certificate = "cert.pem";
        cfg.stealth.trusttunnel.private_key = "key.pem";
        cfg.stealth.trusttunnel.users.push_back({"user1", "password1"});

        return cfg;
    }
} // namespace

// ─── probe::detect() 外层协议探测 ─────────────────────────────────────

/**
 * @brief 测试 recognition::probe::detect() 外层协议探测
 */
TEST(Recognition, DetectAllProtocols)
{
    // 空数据 -> unknown
    EXPECT_TRUE(probe::detect("") == psm::protocol::protocol_type::unknown)
        << "detect: empty -> unknown";

    // SOCKS5 (首字节 0x05)
    std::string socks5 = "\x05\x01\x00";
    EXPECT_TRUE(probe::detect(socks5) == psm::protocol::protocol_type::socks5)
        << "detect: 0x05 -> socks5";

    // TLS (0x16 0x03)
    std::string tls = "\x16\x03\x01\x00\x05";
    EXPECT_TRUE(probe::detect(tls) == psm::protocol::protocol_type::tls)
        << "detect: 0x16 0x03 -> tls";

    // 单字节 0x16 但第二字节不是 0x03 -> shadowsocks fallback
    std::string not_tls = "\x16\x00";
    EXPECT_TRUE(probe::detect(not_tls) == psm::protocol::protocol_type::shadowsocks)
        << "detect: 0x16 0x00 -> shadowsocks (not TLS)";

    // HTTP GET
    EXPECT_TRUE(probe::detect("GET / HTTP/1.1\r\n") == psm::protocol::protocol_type::http)
        << "detect: GET -> http";

    // HTTP POST
    EXPECT_TRUE(probe::detect("POST /api HTTP/1.1\r\n") == psm::protocol::protocol_type::http)
        << "detect: POST -> http";

    // 随机字节 -> shadowsocks fallback
    std::string random = "\x42\x00\xFF\xAB\xCD";
    EXPECT_TRUE(probe::detect(random) == psm::protocol::protocol_type::shadowsocks)
        << "detect: random bytes -> shadowsocks";
}

// ─── SNI 路由测试 ───────────────────────────────────────────────────────

/**
 * @brief 测试 SNI 路由表构建
 */
TEST(Recognition, SNIRouteTableBuild)
{
    auto cfg = make_multi_scheme_config();
    auto table = psm::recognition::route_table::build(cfg);

    EXPECT_TRUE(!table.empty()) << "Route table should not be empty";
    EXPECT_TRUE(table.registered_snis().size() == 5) << "Should have 5 registered SNIs";
}

/**
 * @brief 测试 SNI 路由查询
 */
TEST(Recognition, SNIRouteTableLookup)
{
    auto cfg = make_multi_scheme_config();
    auto table = psm::recognition::route_table::build(cfg);

    // 测试 Reality SNI
    auto schemes = table.lookup("reality.example.com");
    EXPECT_TRUE(schemes.size() == 1) << "Reality SNI should match 1 scheme";
    EXPECT_TRUE(schemes[0] == "reality") << "Should be reality";

    // 测试 ShadowTLS SNI
    schemes = table.lookup("shadowtls.example.com");
    EXPECT_TRUE(schemes.size() == 1) << "ShadowTLS SNI should match 1 scheme";
    EXPECT_TRUE(schemes[0] == "shadowtls") << "Should be shadowtls";

    // 测试 Restls SNI
    schemes = table.lookup("restls.example.com");
    EXPECT_TRUE(schemes.size() == 1) << "Restls SNI should match 1 scheme";
    EXPECT_TRUE(schemes[0] == "restls") << "Should be restls";

    // 测试 AnyTLS SNI
    schemes = table.lookup("anytls.example.com");
    EXPECT_TRUE(schemes.size() == 1) << "AnyTLS SNI should match 1 scheme";
    EXPECT_TRUE(schemes[0] == "anytls") << "Should be anytls";

    // 测试 TrustTunnel SNI
    schemes = table.lookup("trusttunnel.example.com");
    EXPECT_TRUE(schemes.size() == 1) << "TrustTunnel SNI should match 1 scheme";
    EXPECT_TRUE(schemes[0] == "trusttunnel") << "Should be trusttunnel";

    // 测试未知 SNI
    schemes = table.lookup("unknown.example.com");
    EXPECT_TRUE(schemes.empty()) << "Unknown SNI should match none";

    // 测试空 SNI
    schemes = table.lookup("");
    EXPECT_TRUE(schemes.empty()) << "Empty SNI should match none";
}

// ─── FeatureBitmap 测试 ─────────────────────────────────────────────────

/**
 * @brief 测试特征位图构建
 */
TEST(Recognition, FeatureBitmapBuild)
{
    // 测试空特征
    hello_features empty_features;
    auto bitmap = psm::recognition::tls::build_bitmap(empty_features);
    EXPECT_TRUE(bitmap == 0) << "Empty features should produce 0 bitmap";

    // 测试有 SNI
    hello_features sni_features;
    sni_features.server_name = "example.com";
    bitmap = psm::recognition::tls::build_bitmap(sni_features);
    EXPECT_TRUE(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::has_sni))
        << "Should have has_sni bit";

    // 测试有 X25519
    hello_features x25519_features;
    x25519_features.has_x25519 = true;
    bitmap = psm::recognition::tls::build_bitmap(x25519_features);
    EXPECT_TRUE(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::has_x25519))
        << "Should have has_x25519 bit";

    // 测试 session_id=32
    hello_features session_features;
    session_features.session_id_len = 32;
    session_features.session_id.resize(32);
    bitmap = psm::recognition::tls::build_bitmap(session_features);
    EXPECT_TRUE(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::full_session))
        << "Should have has_full_session_id bit";

    // 测试非标准 session_id
    hello_features non_std_features;
    non_std_features.session_id_len = 16;
    non_std_features.session_id.resize(16);
    bitmap = psm::recognition::tls::build_bitmap(non_std_features);
    EXPECT_TRUE(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::nonstd_session))
        << "Should have session_id_non_standard bit";
}

/**
 * @brief 测试 Reality 独占标记检测
 */
TEST(Recognition, FeatureBitmapRealityMarker)
{
    // 测试 Reality 独占标记 [01:08:02]
    hello_features reality_features;
    reality_features.session_id_len = 32;
    reality_features.session_id = {0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    auto bitmap = psm::recognition::tls::build_bitmap(reality_features);
    EXPECT_TRUE(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::reality_marker))
        << "Should have reality_marker bit";
    EXPECT_TRUE(psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::full_session))
        << "Should also have full_session bit";

    // 测试非 Reality 标记
    hello_features non_reality_features;
    non_reality_features.session_id_len = 32;
    non_reality_features.session_id.resize(32);
    non_reality_features.session_id[0] = 0x00;

    bitmap = psm::recognition::tls::build_bitmap(non_reality_features);
    EXPECT_TRUE(!psm::recognition::tls::has_feature(bitmap, psm::recognition::tls::feature_bit::reality_marker))
        << "Should not have reality_marker bit";
}

/**
 * @brief 测试组合特征检测
 */
TEST(Recognition, FeatureBitmapCombined)
{
    // 构建包含多个特征的位图
    hello_features features;
    features.server_name = "example.com";
    features.has_x25519 = true;
    features.session_id_len = 32;
    features.session_id.resize(32);

    auto bitmap = psm::recognition::tls::build_bitmap(features);

    // 测试组合特征
    using fb = psm::recognition::tls::feature_bit;
    auto combined = fb::has_sni | fb::has_x25519 | fb::full_session;
    EXPECT_TRUE(psm::recognition::tls::has_all(bitmap, combined))
        << "Should have all three features";

    // 测试部分匹配
    auto partial = fb::has_sni | fb::has_ech;
    EXPECT_TRUE(!psm::recognition::tls::has_all(bitmap, partial))
        << "Should not have ECH";
}

// ─── Reality sniff 测试 ─────────────────────────────────────────

/**
 * @brief 测试 Reality 独占标记检测（sniff）
 */
TEST(Recognition, RealitySniffExclusive)
{
    psm::stealth::reality::scheme scheme;

    // Reality 独占标记 → 独占命中
    hello_features features;
    features.session_id_len = 32;
    features.session_id = {0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    features.has_x25519 = true;

    auto bitmap = psm::recognition::tls::build_bitmap(features);
    auto result = scheme.sniff(bitmap, features);

    EXPECT_TRUE(result.hit) << "Reality marker should hit";
    EXPECT_TRUE(result.solo) << "Reality marker should be solo (exclusive)";
    EXPECT_TRUE(result.hint >= 900) << "Reality marker should have high hint";

    // 无标记但有 X25519 + session_id=32 → 非独占
    hello_features no_marker_features;
    no_marker_features.session_id_len = 32;
    no_marker_features.session_id.resize(32);
    no_marker_features.has_x25519 = true;

    bitmap = psm::recognition::tls::build_bitmap(no_marker_features);
    result = scheme.sniff(bitmap, features);

    EXPECT_TRUE(result.hit) << "X25519+session_id=32 should hit";
    EXPECT_TRUE(!result.solo) << "Without marker should not be solo";
}

// ─── scheme_registry 测试 ──────────────────────────────────────────────

/**
 * @brief 测试 scheme_registry 注册与查询
 */
TEST(Recognition, SchemeRegistry)
{
    // 注册所有方案
    psm::stealth::register_schemes();
    auto &reg = psm::stealth::scheme_registry::instance();

    EXPECT_TRUE(reg.all().size() >= 4)
        << "registry: at least 4 schemes registered";

    // 按名称查找
    auto reality = reg.find("reality");
    EXPECT_TRUE(reality != nullptr)
        << "registry: find('reality') succeeds";
    EXPECT_TRUE(reality->name() == "reality")
        << "registry: reality name matches";
    EXPECT_TRUE(reality->tier() == 0)
        << "registry: reality should be Tier 0";
    EXPECT_TRUE(reality->unique())
        << "registry: reality should have unique feature";

    auto native = reg.find("native");
    EXPECT_TRUE(native != nullptr)
        << "registry: find('native') succeeds";
    EXPECT_TRUE(native->tier() == 2)
        << "registry: native should be Tier 2";

    // 不存在的方案
    auto unknown = reg.find("nonexistent");
    EXPECT_TRUE(unknown == nullptr)
        << "registry: find('nonexistent') returns nullptr";
}

// ─── 结构体默认值测试 ───────────────────────────────────────────────────

/**
 * @brief 测试 hello_features 默认值
 */
TEST(Recognition, ClientHelloFeaturesDefaults)
{
    hello_features features;

    EXPECT_TRUE(features.server_name.empty())
        << "hello_features: server_name empty";
    EXPECT_TRUE(features.session_id_len == 0)
        << "hello_features: session_id_len = 0";
    EXPECT_TRUE(features.has_x25519 == false)
        << "hello_features: has_x25519 = false";
    EXPECT_TRUE(features.versions.empty())
        << "hello_features: versions empty";
    EXPECT_TRUE(features.session_id.empty())
        << "hello_features: session_id empty";
}

/**
 * @brief 测试 probe_result 默认值
 */
TEST(Recognition, ProbeResultDefaults)
{
    probe::probe_result result;

    EXPECT_TRUE(result.type == psm::protocol::protocol_type::unknown)
        << "probe_result: default type = unknown";
    EXPECT_TRUE(result.pre_read_size == 0)
        << "probe_result: default pre_read_size = 0";
    EXPECT_TRUE(result.ec == psm::fault::code::success)
        << "probe_result: default ec = success";
}

/**
 * @brief 测试 sniff_result 默认值
 */
TEST(Recognition, SniffResultDefaults)
{
    psm::stealth::sniff_result result;

    EXPECT_TRUE(result.hit == false) << "sniff_result: default hit = false";
    EXPECT_TRUE(result.solo == false) << "sniff_result: default solo = false";
    EXPECT_TRUE(result.hint == 0) << "sniff_result: default hint = 0";
}

/**
 * @brief 测试 verify_result 默认值
 */
TEST(Recognition, VerifyResultDefaults)
{
    psm::stealth::verify_result result;

    EXPECT_TRUE(result.score == 0) << "verify_result: default score = 0";
    EXPECT_TRUE(result.solo_flag == 0) << "verify_result: default solo_flag = 0";
}
