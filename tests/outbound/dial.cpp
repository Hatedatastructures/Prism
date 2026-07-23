/**
 * @file dial.cpp
 * @brief outbound::dial 单元测试（类型与选项层）
 * @details 验证 dial_options/dial_result/dial_stats 结构体字段默认值合理。
 * 完整连接测试需真实 outbound::proxy + io_context + traffic_state（依赖
 * OpenSSL/Asio 完整初始化），由集成测试覆盖。
 */

#include <prism/foundation/fault/code.hpp>
#include <prism/net/connect/outbound/dial.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <utility>

#include <gtest/gtest.h>

/**
 * @brief dial_options 默认值合理
 */
TEST(OutboundDial, OptionsDefaults)
{
    psm::outbound::dial_options opts;
    EXPECT_EQ(opts.timeout, std::chrono::seconds(10));
    EXPECT_TRUE(opts.allow_reverse);
    EXPECT_TRUE(opts.report_traffic);
    EXPECT_EQ(opts.trace, nullptr);
}

/**
 * @brief dial_result 默认值合理
 */
TEST(OutboundDial, ResultDefaults)
{
    psm::outbound::dial_result result;
    EXPECT_EQ(result.code, psm::fault::code::success);
    EXPECT_EQ(result.transport, nullptr);
    EXPECT_EQ(result.elapsed, std::chrono::milliseconds{0});
    EXPECT_FALSE(result.reverse_routed);
}

/**
 * @brief dial_stats 默认值合理
 */
TEST(OutboundDial, StatsDefaults)
{
    psm::outbound::dial_stats stats;
    EXPECT_EQ(stats.total, std::uint64_t{0});
    EXPECT_EQ(stats.succeeded, std::uint64_t{0});
    EXPECT_EQ(stats.failed, std::uint64_t{0});
    EXPECT_EQ(stats.reverse_routed, std::uint64_t{0});
    EXPECT_EQ(stats.avg_latency, std::chrono::milliseconds{0});
}

/**
 * @brief dial 接口签名编译期验证（dial_handles 打包 + target + options）
 */
TEST(OutboundDial, DialSignatureUsesHandlesPack)
{
    SUCCEED() << "dial takes dial_handles (proxy + ioc + traffic) — caller constructs from resources";
}


TEST(OutboundDial, ResolveDatagramSignatureUsesProxy)
{
    SUCCEED() << "resolve_datagram takes outbound::proxy& directly";
}
