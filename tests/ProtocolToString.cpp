/**
 * @file ProtocolToString.cpp
 * @brief 协议枚举到字符串转换单元测试
 * @details 验证 psm::protocol::to_string_view() 的核心功能，包括：
 * 1. 所有 protocol_type 枚举值的正确字符串映射
 * 2. 默认分支（未知枚举值）回退到 "unknown"
 * 3. 测试覆盖率验证，确保枚举值数量与测试用例一致
 */

#include <prism/memory.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#include <format>
#include <string_view>

namespace
{
    psm::testing::TestRunner runner("ProtocolToString");
}

/**
 * @brief 测试所有协议类型的 to_string_view 映射
 */
void TestTostringviewAllProtocols()
{
    runner.LogInfo("=== Testing to_string_view() for all protocols ===");

    struct TestCase
    {
        psm::protocol::protocol_type type;
        std::string_view expected;
    };

    constexpr TestCase cases[] = {
        {psm::protocol::protocol_type::unknown,    "unknown"},
        {psm::protocol::protocol_type::http,       "http"},
        {psm::protocol::protocol_type::socks5,     "socks5"},
        {psm::protocol::protocol_type::trojan,     "trojan"},
        {psm::protocol::protocol_type::vless,      "vless"},
        {psm::protocol::protocol_type::shadowsocks,"shadowsocks"},
        {psm::protocol::protocol_type::tls,        "tls"},
    };

    for (const auto &tc : cases)
    {
        const std::string_view result = psm::protocol::to_string_view(tc.type);
        if (result != tc.expected)
        {
            runner.LogFail(std::format(
                "to_string_view({}) = \"{}\", expected \"{}\"",
                static_cast<int>(tc.type), result, tc.expected));
            return;
        }
    }

    runner.LogPass("to_string_view() for all protocol types");
}

/**
 * @brief 测试默认分支回退和覆盖率验证
 */
void TestTostringviewCoverage()
{
    runner.LogInfo("=== Testing to_string_view() coverage ===");

    // 验证测试用例数量与协议枚举值数量一致
    constexpr int expected_count = 7; // unknown, http, socks5, trojan, vless, shadowsocks, tls
    constexpr int actual_count = static_cast<int>(psm::protocol::protocol_type::tls) + 1;
    if (actual_count != expected_count)
    {
        runner.LogFail(std::format(
            "Protocol enum count mismatch: expected {}, got {}", expected_count, actual_count));
        return;
    }

    // 验证默认分支：构造一个超出范围的枚举值，应回退到 "unknown"
    const auto invalid = static_cast<psm::protocol::protocol_type>(999);
    const std::string_view result = psm::protocol::to_string_view(invalid);
    if (result != "unknown")
    {
        runner.LogFail(std::format(
            "to_string_view(invalid) = \"{}\", expected \"unknown\"", result));
        return;
    }

    runner.LogPass("to_string_view() coverage and default fallback");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行协议字符串映射和覆盖率测试，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("Starting ProtocolToString tests...");

    TestTostringviewAllProtocols();
    TestTostringviewCoverage();

    runner.LogInfo("ProtocolToString tests completed.");

    return runner.Summary();
}
