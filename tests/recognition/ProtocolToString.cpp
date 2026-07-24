/**
 * @file ProtocolToString.cpp
 * @brief 协议枚举到字符串转换单元测试
 * @details 验证 psm::connect::to_string_view() 的核心功能，包括：
 * 1. 所有 protocol_type 枚举值的正确字符串映射
 * 2. 默认分支（未知枚举值）回退到 "unknown"
 * 3. 测试覆盖率验证，确保枚举值数量与测试用例一致
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <format>
#include <string_view>

/**
 * @brief 测试所有协议类型的 to_string_view 映射
 */
TEST(ProtocolToString, AllProtocols)
{
    struct TestCase
    {
        psm::connect::protocol_type type;
        std::string_view expected;
    };

    constexpr TestCase cases[] = {
        {psm::connect::protocol_type::unknown,    "unknown"},
        {psm::connect::protocol_type::http,       "http"},
        {psm::connect::protocol_type::socks5,     "socks5"},
        {psm::connect::protocol_type::trojan,     "trojan"},
        {psm::connect::protocol_type::vless,      "vless"},
        {psm::connect::protocol_type::shadowsocks,"shadowsocks"},
        {psm::connect::protocol_type::tls,        "tls"},
    };

    for (const auto &tc : cases)
    {
        const std::string_view result = psm::connect::to_string_view(tc.type);
        EXPECT_TRUE(result == tc.expected)
            << std::format("to_string_view({}) = \"{}\", expected \"{}\"",
                           static_cast<int>(tc.type), result, tc.expected);
    }
}

/**
 * @brief 测试默认分支回退和覆盖率验证
 */
TEST(ProtocolToString, CoverageAndDefaultFallback)
{
    // 验证测试用例数量与协议枚举值数量一致
    constexpr int expected_count = 7; // unknown, http, socks5, trojan, vless, shadowsocks, tls
    constexpr int actual_count = static_cast<int>(psm::connect::protocol_type::tls) + 1;
    EXPECT_TRUE(actual_count == expected_count)
        << std::format("Protocol enum count mismatch: expected {}, got {}", expected_count, actual_count);

    // 验证默认分支：构造一个超出范围的枚举值，应回退到 "unknown"
    const auto invalid = static_cast<psm::connect::protocol_type>(999);
    const std::string_view result = psm::connect::to_string_view(invalid);
    EXPECT_TRUE(result == "unknown")
        << std::format("to_string_view(invalid) = \"{}\", expected \"unknown\"", result);
}
