/**
 * @file Recognition.cpp
 * @brief Recognition 模块单元测试
 * @details 测试 recognition 模块的核心功能，包括：
 * 1. confidence 枚举值顺序验证
 * 2. probe::detect() 外层协议探测
 * 3. reality scheme detect() 各置信度级别（high/medium/low/none）
 * 4. scheme_registry 注册与查询
 * 5. analysis_result / client_hello_features 默认值
 */

#include <prism/recognition/confidence.hpp>
#include <prism/recognition/result.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/recognition/probe/probe.hpp>
#include <prism/stealth/reality/scheme.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/memory.hpp>
#include <prism/trace.hpp>
#include <prism/config.hpp>
#include "common/TestRunner.hpp"

#include <string>

#ifdef WIN32
#include <windows.h>
#endif

namespace probe = psm::recognition::probe;
using psm::protocol::tls::client_hello_features;
using psm::recognition::confidence;

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
} // namespace

// ─── confidence 枚举 ──────────────────────────────────────────────────

/**
 * @brief 验证 confidence 枚举值顺序：high=0, medium=1, low=2, none=3
 * @details 确保升序排序后 high 排在最前面（值最小优先）。
 */
void TestConfidenceOrdering(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestConfidenceOrdering ===");

    runner.Check(static_cast<uint8_t>(confidence::high) == 0,
                 "confidence::high == 0");
    runner.Check(static_cast<uint8_t>(confidence::medium) == 1,
                 "confidence::medium == 1");
    runner.Check(static_cast<uint8_t>(confidence::low) == 2,
                 "confidence::low == 2");
    runner.Check(static_cast<uint8_t>(confidence::none) == 3,
                 "confidence::none == 3");
    runner.Check(static_cast<uint8_t>(confidence::high) < static_cast<uint8_t>(confidence::none),
                 "high < none (ascending sort puts high first)");
}

// ─── probe::detect() 外层协议探测 ─────────────────────────────────────

/**
 * @brief 测试 recognition::probe::detect() 外层协议探测
 */
void TestDetectAllProtocols(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestDetectAllProtocols ===");

    // 空数据 -> unknown
    runner.Check(probe::detect("") == psm::protocol::protocol_type::unknown,
                 "detect: empty -> unknown");

    // SOCKS5 (首字节 0x05)
    std::string socks5 = "\x05\x01\x00";
    runner.Check(probe::detect(socks5) == psm::protocol::protocol_type::socks5,
                 "detect: 0x05 -> socks5");

    // TLS (0x16 0x03)
    std::string tls = "\x16\x03\x01\x00\x05";
    runner.Check(probe::detect(tls) == psm::protocol::protocol_type::tls,
                 "detect: 0x16 0x03 -> tls");

    // 单字节 0x16 但第二字节不是 0x03 -> shadowsocks fallback
    std::string not_tls = "\x16\x00";
    runner.Check(probe::detect(not_tls) == psm::protocol::protocol_type::shadowsocks,
                 "detect: 0x16 0x00 -> shadowsocks (not TLS)");

    // HTTP GET
    runner.Check(probe::detect("GET / HTTP/1.1\r\n") == psm::protocol::protocol_type::http,
                 "detect: GET -> http");

    // HTTP POST
    runner.Check(probe::detect("POST /api HTTP/1.1\r\n") == psm::protocol::protocol_type::http,
                 "detect: POST -> http");

    // 随机字节 -> shadowsocks fallback
    std::string random = "\x42\x00\xFF\xAB\xCD";
    runner.Check(probe::detect(random) == psm::protocol::protocol_type::shadowsocks,
                 "detect: random bytes -> shadowsocks");
}

// ─── reality scheme detect() ───────────────────────────────────────────

/**
 * @brief 测试 reality scheme detect() 高置信度路径
 * @details SNI 匹配 + 32字节 session_id + X25519 key_share -> high
 */
void TestRealityDetectHigh(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityDetectHigh ===");

    auto cfg = make_reality_config();
    psm::stealth::reality::scheme scheme;

    client_hello_features features;
    features.server_name = "example.com";
    features.session_id_len = 32;
    features.has_x25519 = true;

    auto result = scheme.detect(features, cfg);

    runner.Check(result.confidence == confidence::high,
                 "reality::detect: full features -> high");
}

/**
 * @brief 测试 reality scheme detect() 中置信度路径
 * @details SNI 匹配 + session_id != 32 + X25519 -> medium
 */
void TestRealityDetectMedium(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityDetectMedium ===");

    auto cfg = make_reality_config();
    psm::stealth::reality::scheme scheme;

    client_hello_features features;
    features.server_name = "example.com";
    features.session_id_len = 16; // 非 32 字节
    features.has_x25519 = true;

    auto result = scheme.detect(features, cfg);

    runner.Check(result.confidence == confidence::medium,
                 "reality::detect: session_id != 32, X25519=true -> medium");
}

/**
 * @brief 测试 reality scheme detect() 低置信度路径
 * @details SNI 匹配 + X25519=false -> low
 */
void TestRealityDetectLow(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityDetectLow ===");

    auto cfg = make_reality_config();
    psm::stealth::reality::scheme scheme;

    client_hello_features features;
    features.server_name = "example.com";
    features.session_id_len = 32;
    features.has_x25519 = false;

    auto result = scheme.detect(features, cfg);

    runner.Check(result.confidence == confidence::low,
                 "reality::detect: SNI match, no X25519 -> low");
}

/**
 * @brief 测试 reality scheme detect() 无匹配路径
 * @details SNI 不匹配 -> none
 */
void TestRealityDetectNone(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityDetectNone ===");

    auto cfg = make_reality_config();
    psm::stealth::reality::scheme scheme;

    client_hello_features features;
    features.server_name = "attacker.com"; // 不匹配
    features.session_id_len = 32;
    features.has_x25519 = true;

    auto result = scheme.detect(features, cfg);

    runner.Check(result.confidence == confidence::none,
                 "reality::detect: SNI mismatch -> none");
}

/**
 * @brief 测试 reality scheme is_enabled()
 * @details 配置完整时返回 true，空配置时返回 false
 */
void TestRealityIsEnabled(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityIsEnabled ===");

    psm::stealth::reality::scheme scheme;

    // 配置完整的 reality -> enabled
    auto cfg = make_reality_config();
    runner.Check(scheme.is_enabled(cfg) == true,
                 "reality::is_enabled: full config -> true");

    // 空配置 -> disabled
    psm::config empty_cfg;
    runner.Check(scheme.is_enabled(empty_cfg) == false,
                 "reality::is_enabled: empty config -> false");
}

/**
 * @brief 测试 reality SNI 匹配行为
 * @details 覆盖四种情况：空 SNI、空 server_names、单匹配、不匹配
 */
void TestRealitySniMatch(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealitySniMatch ===");

    psm::stealth::reality::scheme scheme;

    // 空 SNI -> none
    {
        auto cfg = make_reality_config();
        client_hello_features features;
        features.session_id_len = 32;
        features.has_x25519 = true;
        // server_name 保持默认空值

        auto result = scheme.detect(features, cfg);
        runner.Check(result.confidence == confidence::none,
                     "reality SNI: empty SNI -> none");
    }

    // 空 server_names -> none
    {
        psm::config cfg;
        cfg.stealth.reality.dest = "example.com:443";
        cfg.stealth.reality.private_key = "dGVzdA==";
        // server_names 保持默认空

        client_hello_features features;
        features.server_name = "example.com";
        features.session_id_len = 32;
        features.has_x25519 = true;

        auto result = scheme.detect(features, cfg);
        runner.Check(result.confidence == confidence::none,
                     "reality SNI: empty server_names -> none");
    }

    // 单个 SNI 匹配 -> low (无 X25519)
    {
        auto cfg = make_reality_config();
        client_hello_features features;
        features.server_name = "example.com";
        // 无 X25519，因此返回 low

        auto result = scheme.detect(features, cfg);
        runner.Check(result.confidence == confidence::low,
                     "reality SNI: single match -> low");
    }

    // SNI 不匹配 -> none
    {
        auto cfg = make_reality_config();
        client_hello_features features;
        features.server_name = "evil.com";
        features.session_id_len = 32;
        features.has_x25519 = true;

        auto result = scheme.detect(features, cfg);
        runner.Check(result.confidence == confidence::none,
                     "reality SNI: no match -> none");
    }
}

// ─── scheme_registry ──────────────────────────────────────────────────

/**
 * @brief 测试 scheme_registry 注册与查询
 */
void TestSchemeRegistry(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestSchemeRegistry ===");

    // 注册所有方案
    psm::stealth::register_all_schemes();
    auto &reg = psm::stealth::scheme_registry::instance();

    runner.Check(reg.all().size() >= 4,
                 "registry: at least 4 schemes registered");

    // 按名称查找
    auto reality = reg.find("reality");
    runner.Check(reality != nullptr,
                 "registry: find('reality') succeeds");
    runner.Check(reality->name() == "reality",
                 "registry: reality name matches");

    auto native = reg.find("native");
    runner.Check(native != nullptr,
                 "registry: find('native') succeeds");

    // 不存在的方案
    auto unknown = reg.find("nonexistent");
    runner.Check(unknown == nullptr,
                 "registry: find('nonexistent') returns nullptr");
}

// ─── 结构体默认值 ─────────────────────────────────────────────────────

/**
 * @brief 测试 analysis_result 默认值
 */
void TestAnalysisResultDefaults(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestAnalysisResultDefaults ===");

    psm::recognition::analysis_result result;

    runner.Check(result.confidence == confidence::none,
                 "analysis_result: default confidence = none");
    runner.Check(result.error == psm::fault::code::success,
                 "analysis_result: default error = success");
    runner.Check(result.candidates.empty(),
                 "analysis_result: default candidates empty");
}

/**
 * @brief 测试 client_hello_features 默认值
 */
void TestClientHelloFeaturesDefaults(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestClientHelloFeaturesDefaults ===");

    client_hello_features features;

    runner.Check(features.server_name.empty(),
                 "client_hello_features: server_name empty");
    runner.Check(features.session_id_len == 0,
                 "client_hello_features: session_id_len = 0");
    runner.Check(features.has_x25519 == false,
                 "client_hello_features: has_x25519 = false");
    runner.Check(features.versions.empty(),
                 "client_hello_features: versions empty");
    runner.Check(features.session_id.empty(),
                 "client_hello_features: session_id empty");
    runner.Check(features.raw_record.empty(),
                 "client_hello_features: raw_record empty");
    runner.Check(features.raw_hs_msg.empty(),
                 "client_hello_features: raw_hs_msg empty");
}

/**
 * @brief 测试 probe_result 默认值
 */
void TestProbeResultDefaults(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestProbeResultDefaults ===");

    probe::probe_result result;

    runner.Check(result.type == psm::protocol::protocol_type::unknown,
                 "probe_result: default type = unknown");
    runner.Check(result.pre_read_size == 0,
                 "probe_result: default pre_read_size = 0");
    runner.Check(result.ec == psm::fault::code::success,
                 "probe_result: default ec = success");
}

/**
 * @brief 测试 probe_result 辅助方法：success()、preload_view()、preload_bytes()
 */
void TestProbeResultHelpers(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestProbeResultHelpers ===");

    // success() 有效类型 + 无错误 -> true
    {
        probe::probe_result result;
        result.type = psm::protocol::protocol_type::tls;
        result.ec = psm::fault::code::success;
        runner.Check(result.success() == true,
                     "probe_result::success: valid type + no error -> true");
    }

    // success() 未知类型 -> false
    {
        probe::probe_result result;
        result.type = psm::protocol::protocol_type::unknown;
        runner.Check(result.success() == false,
                     "probe_result::success: unknown type -> false");
    }

    // success() 有错误码 -> false
    {
        probe::probe_result result;
        result.type = psm::protocol::protocol_type::tls;
        result.ec = psm::fault::code::timeout;
        runner.Check(result.success() == false,
                     "probe_result::success: with error -> false");
    }

    // preload_view() 和 preload_bytes()
    {
        probe::probe_result result;
        result.type = psm::protocol::protocol_type::http;
        result.ec = psm::fault::code::success;
        std::string data = "GET / HTTP/1.1\r\n";
        auto *raw = reinterpret_cast<std::byte *>(result.pre_read_data.data());
        for (std::size_t i = 0; i < data.size(); ++i)
            raw[i] = std::byte(data[i]);
        result.pre_read_size = data.size();

        auto view = result.preload_view();
        runner.Check(view == "GET / HTTP/1.1\r\n",
                     "probe_result::preload_view: content correct");
        runner.Check(view.size() == data.size(),
                     "probe_result::preload_view: size correct");

        auto bytes = result.preload_bytes();
        runner.Check(bytes.size() == data.size(),
                     "probe_result::preload_bytes: size correct");
        runner.Check(static_cast<unsigned char>(bytes[0]) == static_cast<unsigned char>('G'),
                     "probe_result::preload_bytes: first byte = 'G'");
    }
}

// ─── 主入口 ───────────────────────────────────────────────────────────

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行所有识别模块测试用例。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    psm::testing::TestRunner runner("Recognition");
    runner.LogInfo("Starting Recognition tests...");

    TestConfidenceOrdering(runner);
    TestDetectAllProtocols(runner);
    TestRealityDetectHigh(runner);
    TestRealityDetectMedium(runner);
    TestRealityDetectLow(runner);
    TestRealityDetectNone(runner);
    TestRealityIsEnabled(runner);
    TestRealitySniMatch(runner);
    TestSchemeRegistry(runner);
    TestAnalysisResultDefaults(runner);
    TestClientHelloFeaturesDefaults(runner);
    TestProbeResultDefaults(runner);
    TestProbeResultHelpers(runner);

    runner.LogInfo("Recognition tests completed.");

    return runner.Summary();
}
