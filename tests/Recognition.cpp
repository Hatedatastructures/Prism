/**
 * @file Recognition.cpp
 * @brief Recognition 模块单元测试
 * @details 测试 recognition 模块的核心功能，包括：
 * 1. confidence 枚举值顺序验证
 * 2. probe::detect() 外层协议探测
 * 3. reality 分析器各置信度级别（high/medium/low/none）
 * 4. reality::is_enabled() 启用检测
 * 5. reality SNI 匹配行为（通过 analyze 间接验证私有方法 check_sni_match）
 * 6. ech 分析器
 * 7. anytls 分析器
 * 8. registry 注册与排序
 * 9. execution_priority 默认值
 * 10. analysis_result / arrival_features / probe_result 默认值与辅助方法
 */

#include <prism/recognition/confidence.hpp>
#include <prism/recognition/feature.hpp>
#include <prism/recognition/result.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/recognition/probe/probe.hpp>
#include <prism/recognition/arrival/reality.hpp>
#include <prism/recognition/arrival/ech.hpp>
#include <prism/recognition/arrival/anytls.hpp>
#include <prism/recognition/arrival/registry.hpp>
#include <prism/recognition/handshake/priority.hpp>
#include <prism/memory.hpp>
#include <prism/trace.hpp>
#include <prism/config.hpp>
#include "common/TestRunner.hpp"

#include <string>

#ifdef WIN32
#include <windows.h>
#endif

namespace arrival = psm::recognition::arrival;
namespace probe = psm::recognition::probe;
using psm::recognition::confidence;
using psm::recognition::arrival_features;

namespace
{
    /**
     * @brief 用于 registry 单元测试的 Mock feature 实现
     */
    class MockFeature final : public arrival::feature
    {
    public:
        MockFeature(std::string name, confidence result, bool enabled = true) noexcept
            : name_(std::move(name)), result_(result), enabled_(enabled)
        {
        }

        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return name_;
        }

        [[nodiscard]] auto analyze(
            [[maybe_unused]] const arrival_features &features,
            [[maybe_unused]] const psm::config &cfg) const -> confidence override
        {
            return result_;
        }

        [[nodiscard]] auto is_enabled(
            [[maybe_unused]] const psm::config &cfg) const noexcept -> bool override
        {
            return enabled_;
        }

    private:
        std::string name_;
        confidence result_;
        bool enabled_;
    };
} // namespace

/**
 * @brief 构建一个启用了 reality 的配置对象
 */
static auto make_reality_config() -> psm::config
{
    psm::config cfg;
    cfg.stealth.reality.dest = "example.com:443";
    cfg.stealth.reality.private_key = "dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVzdHRlc3Q=";
    cfg.stealth.reality.server_names.push_back("example.com");
    return cfg;
}

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
    // 升序排序时值小的在前，因此 high(0) 排在 none(3) 之前
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

// ─── reality 分析器 ───────────────────────────────────────────────────

/**
 * @brief 测试 reality::analyze() 高置信度路径
 * @details SNI 匹配 + 32字节 session_id + X25519 key_share -> high
 */
void TestRealityAnalyzeHigh(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityAnalyzeHigh ===");

    auto cfg = make_reality_config();

    arrival_features features;
    features.server_name = "example.com";
    features.session_id_len = 32;
    features.has_x25519_key_share = true;

    arrival::reality analyzer;
    auto result = analyzer.analyze(features, cfg);

    runner.Check(result == confidence::high,
                 "reality::analyze: full features -> high");
}

/**
 * @brief 测试 reality::analyze() 中置信度路径
 * @details SNI 匹配 + session_id != 32 + X25519 -> medium
 */
void TestRealityAnalyzeMedium(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityAnalyzeMedium ===");

    auto cfg = make_reality_config();

    arrival_features features;
    features.server_name = "example.com";
    features.session_id_len = 16; // 非 32 字节
    features.has_x25519_key_share = true;

    arrival::reality analyzer;
    auto result = analyzer.analyze(features, cfg);

    runner.Check(result == confidence::medium,
                 "reality::analyze: session_id != 32, X25519=true -> medium");
}

/**
 * @brief 测试 reality::analyze() 低置信度路径
 * @details SNI 匹配 + X25519=false -> low
 */
void TestRealityAnalyzeLow(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityAnalyzeLow ===");

    auto cfg = make_reality_config();

    arrival_features features;
    features.server_name = "example.com";
    features.session_id_len = 32;
    features.has_x25519_key_share = false;

    arrival::reality analyzer;
    auto result = analyzer.analyze(features, cfg);

    runner.Check(result == confidence::low,
                 "reality::analyze: SNI match, no X25519 -> low");
}

/**
 * @brief 测试 reality::analyze() 无匹配路径
 * @details SNI 不匹配 -> none
 */
void TestRealityAnalyzeNone(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityAnalyzeNone ===");

    auto cfg = make_reality_config();

    arrival_features features;
    features.server_name = "attacker.com"; // 不匹配
    features.session_id_len = 32;
    features.has_x25519_key_share = true;

    arrival::reality analyzer;
    auto result = analyzer.analyze(features, cfg);

    runner.Check(result == confidence::none,
                 "reality::analyze: SNI mismatch -> none");
}

/**
 * @brief 测试 reality::is_enabled()
 * @details 配置完整时返回 true，空配置时返回 false
 */
void TestRealityIsEnabled(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealityIsEnabled ===");

    arrival::reality analyzer;

    // 配置完整的 reality -> enabled
    auto cfg = make_reality_config();
    runner.Check(analyzer.is_enabled(cfg) == true,
                 "reality::is_enabled: full config -> true");

    // 空配置 -> disabled
    psm::config empty_cfg;
    runner.Check(analyzer.is_enabled(empty_cfg) == false,
                 "reality::is_enabled: empty config -> false");
}

/**
 * @brief 测试 reality SNI 匹配行为（通过 analyze() 间接验证私有方法 check_sni_match）
 * @details 覆盖四种情况：空 SNI、空 server_names、单匹配、不匹配
 */
void TestRealitySniMatch(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRealitySniMatch ===");

    arrival::reality analyzer;

    // 空 SNI -> check_sni_match 返回 false -> analyze 返回 none
    {
        auto cfg = make_reality_config();
        arrival_features features;
        features.session_id_len = 32;
        features.has_x25519_key_share = true;
        // server_name 保持默认空值

        auto result = analyzer.analyze(features, cfg);
        runner.Check(result == confidence::none,
                     "reality SNI: empty SNI -> none (check_sni_match false)");
    }

    // 空 server_names -> check_sni_match 返回 false -> analyze 返回 none
    {
        psm::config cfg;
        cfg.stealth.reality.dest = "example.com:443";
        cfg.stealth.reality.private_key = "dGVzdA==";
        // server_names 保持默认空

        arrival_features features;
        features.server_name = "example.com";
        features.session_id_len = 32;
        features.has_x25519_key_share = true;

        auto result = analyzer.analyze(features, cfg);
        runner.Check(result == confidence::none,
                     "reality SNI: empty server_names -> none (check_sni_match false)");
    }

    // 单个 SNI 匹配 -> check_sni_match 返回 true -> analyze 返回至少 low
    {
        auto cfg = make_reality_config();
        arrival_features features;
        features.server_name = "example.com";
        // 无 X25519，因此返回 low

        auto result = analyzer.analyze(features, cfg);
        runner.Check(result == confidence::low,
                     "reality SNI: single match -> low (check_sni_match true)");
    }

    // SNI 不匹配 -> check_sni_match 返回 false -> analyze 返回 none
    {
        auto cfg = make_reality_config();
        arrival_features features;
        features.server_name = "evil.com";
        features.session_id_len = 32;
        features.has_x25519_key_share = true;

        auto result = analyzer.analyze(features, cfg);
        runner.Check(result == confidence::none,
                     "reality SNI: no match -> none (check_sni_match false)");
    }
}

// ─── ech 分析器 ───────────────────────────────────────────────────────

/**
 * @brief 测试 ech::analyze()
 * @details has_ech_extension=true -> high, false -> none
 */
void TestEchAnalyze(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestEchAnalyze ===");

    arrival::ech analyzer;
    psm::config cfg;

    // ECH 扩展存在 -> high
    {
        arrival_features features;
        features.has_ech_extension = true;
        auto result = analyzer.analyze(features, cfg);
        runner.Check(result == confidence::high,
                     "ech::analyze: has_ech_extension=true -> high");
    }

    // ECH 扩展不存在 -> none
    {
        arrival_features features;
        features.has_ech_extension = false;
        auto result = analyzer.analyze(features, cfg);
        runner.Check(result == confidence::none,
                     "ech::analyze: has_ech_extension=false -> none");
    }
}

// ─── anytls 分析器 ────────────────────────────────────────────────────

/**
 * @brief 测试 anytls::analyze()
 * @details anytls 在 ClientHello 中无明显特征，始终返回 none
 */
void TestAnytlsAnalyze(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestAnytlsAnalyze ===");

    arrival::anytls analyzer;
    psm::config cfg;
    arrival_features features;

    auto result = analyzer.analyze(features, cfg);
    runner.Check(result == confidence::none,
                 "anytls::analyze: always returns none");
    runner.Check(analyzer.is_enabled(cfg) == false,
                 "anytls::is_enabled: always returns false");
}

// ─── registry 注册表 ──────────────────────────────────────────────────

/**
 * @brief 测试 registry 注册 feature
 * @details 创建新 registry（非单例），添加 mock feature，验证 features() 包含它
 */
void TestRegistryRegistration(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRegistryRegistration ===");

    arrival::registry reg;

    auto mock = std::make_shared<MockFeature>("mock_test", confidence::high);
    reg.add(mock);

    runner.Check(reg.features().size() == 1,
                 "registry: features().size() == 1 after add");
    runner.Check(reg.features()[0]->name() == "mock_test",
                 "registry: feature name matches 'mock_test'");
}

/**
 * @brief 测试 registry::analyze() 按置信度排序
 * @details 添加 high/medium/low 三个 mock feature，验证结果按 confidence 升序排列
 */
void TestRegistryAnalyzeSorting(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRegistryAnalyzeSorting ===");

    arrival::registry reg;
    reg.add(std::make_shared<MockFeature>("low_feat", confidence::low));
    reg.add(std::make_shared<MockFeature>("high_feat", confidence::high));
    reg.add(std::make_shared<MockFeature>("medium_feat", confidence::medium));

    arrival_features features;
    psm::config cfg;

    auto result = reg.analyze(features, cfg);

    runner.Check(result.candidates.size() == 3,
                 "registry::analyze: 3 candidates");
    runner.Check(result.confidence == confidence::high,
                 "registry::analyze: overall confidence = high");
    // 按置信度升序排列，值小的在前（high=0 最先）
    runner.Check(std::string_view(result.candidates[0]) == "high_feat",
                 "registry::analyze: [0] = high_feat");
    runner.Check(std::string_view(result.candidates[1]) == "medium_feat",
                 "registry::analyze: [1] = medium_feat");
    runner.Check(std::string_view(result.candidates[2]) == "low_feat",
                 "registry::analyze: [2] = low_feat");
}

/**
 * @brief 测试 registry::analyze() 空注册表
 * @details 无任何 feature 的 registry，返回空 candidates 和 confidence::none
 */
void TestRegistryAnalyzeEmpty(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestRegistryAnalyzeEmpty ===");

    arrival::registry reg;

    arrival_features features;
    psm::config cfg;

    auto result = reg.analyze(features, cfg);

    runner.Check(result.candidates.empty(),
                 "registry::analyze: empty candidates");
    runner.Check(result.confidence == confidence::none,
                 "registry::analyze: confidence = none");
}

// ─── execution_priority 默认值 ────────────────────────────────────────

/**
 * @brief 测试 execution_priority::default_order()
 * @details 验证默认模式为 hybrid，顺序为 ["reality","shadowtls","restls","native"]
 */
void TestExecutionPriorityDefault(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestExecutionPriorityDefault ===");

    using namespace psm::recognition::handshake;
    auto def = execution_priority::default_order();

    runner.Check(def.mode == priority_mode::hybrid,
                 "default_order: mode = hybrid");
    runner.Check(def.order.size() == 4,
                 "default_order: order.size() == 4");
    runner.Check(std::string_view(def.order[0]) == "reality",
                 "default_order: [0] = reality");
    runner.Check(std::string_view(def.order[1]) == "shadowtls",
                 "default_order: [1] = shadowtls");
    runner.Check(std::string_view(def.order[2]) == "restls",
                 "default_order: [2] = restls");
    runner.Check(std::string_view(def.order[3]) == "native",
                 "default_order: [3] = native");
    runner.Check(def.skip_low_confidence == false,
                 "default_order: skip_low_confidence = false");
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
 * @brief 测试 arrival_features 默认值
 */
void TestArrivalFeaturesDefaults(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestArrivalFeaturesDefaults ===");

    arrival_features features;

    runner.Check(features.server_name.empty(),
                 "arrival_features: server_name empty");
    runner.Check(features.session_id_len == 0,
                 "arrival_features: session_id_len = 0");
    runner.Check(features.has_x25519_key_share == false,
                 "arrival_features: has_x25519_key_share = false");
    runner.Check(!features.x25519_public_key.has_value(),
                 "arrival_features: x25519_public_key = nullopt");
    runner.Check(features.supported_versions.empty(),
                 "arrival_features: supported_versions empty");
    runner.Check(features.has_ech_extension == false,
                 "arrival_features: has_ech_extension = false");
    runner.Check(!features.ech_config_id.has_value(),
                 "arrival_features: ech_config_id = nullopt");
    runner.Check(features.alpn_protocols.empty(),
                 "arrival_features: alpn_protocols empty");
    runner.Check(features.session_id.empty(),
                 "arrival_features: session_id empty");
    runner.Check(features.raw_arrival.empty(),
                 "arrival_features: raw_arrival empty");
    runner.Check(features.raw_handshake_message.empty(),
                 "arrival_features: raw_handshake_message empty");
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
        auto* raw = reinterpret_cast<std::byte*>(result.pre_read_data.data());
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
    TestRealityAnalyzeHigh(runner);
    TestRealityAnalyzeMedium(runner);
    TestRealityAnalyzeLow(runner);
    TestRealityAnalyzeNone(runner);
    TestRealityIsEnabled(runner);
    TestRealitySniMatch(runner);
    TestEchAnalyze(runner);
    TestAnytlsAnalyze(runner);
    TestRegistryRegistration(runner);
    TestRegistryAnalyzeSorting(runner);
    TestRegistryAnalyzeEmpty(runner);
    TestExecutionPriorityDefault(runner);
    TestAnalysisResultDefaults(runner);
    TestArrivalFeaturesDefaults(runner);
    TestProbeResultDefaults(runner);
    TestProbeResultHelpers(runner);

    runner.LogInfo("Recognition tests completed.");

    return runner.Summary();
}
