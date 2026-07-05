/**
 * @file dial.cpp
 * @brief outbound::dial 单元测试（类型与选项层）
 * @details 验证 dial_options/dial_result/dial_stats 结构体字段和 dial 的
 * nullptr handle 失败路径。完整连接测试需真实 worker::resources（依赖
 * OpenSSL/Asio 完整初始化），由集成测试覆盖。
 */

#include <prism/foundation/fault/code.hpp>
#include <prism/instance/outbound/dial.hpp>
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
    EXPECT_FALSE(result.dns_cache_hit);
    EXPECT_FALSE(result.pool_hit);
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
    EXPECT_EQ(stats.cache_hits, std::uint64_t{0});
    EXPECT_EQ(stats.pool_hits, std::uint64_t{0});
    EXPECT_EQ(stats.ipv6_rejected, std::uint64_t{0});
    EXPECT_EQ(stats.reverse_routed, std::uint64_t{0});
    EXPECT_EQ(stats.avg_latency, std::chrono::milliseconds{0});
}

/**
 * @brief dial 在 handle 为空时返 resource_unavailable
 */
TEST(OutboundDial, FailsWithNullHandle)
{
    psm::protocol::target target;
    target.host = psm::memory::string{"127.0.0.1", psm::memory::current_resource()};
    target.port = psm::memory::string{"80", psm::memory::current_resource()};
    target.positive = true;

    psm::outbound::dial_options opts;

    auto coro = [&]() -> boost::asio::awaitable<void>
    {
        auto result = co_await psm::outbound::dial(nullptr, target, opts);
        EXPECT_EQ(result.code, psm::fault::code::resource_unavailable);
        EXPECT_EQ(result.transport, nullptr);
    };

    boost::asio::io_context ioc;
    boost::asio::co_spawn(ioc, coro(), boost::asio::detached);
    ioc.run();
}

/**
 * @brief resolve_datagram 在 handle 为空时返 resource_unavailable
 */
TEST(OutboundDial, ResolveDatagramFailsWithNullHandle)
{
    auto coro = [&]() -> boost::asio::awaitable<void>
    {
        auto [ec, ep] = co_await psm::outbound::resolve_datagram(nullptr, "127.0.0.1", "53");
        EXPECT_EQ(ec, psm::fault::code::resource_unavailable);
    };

    boost::asio::io_context ioc;
    boost::asio::co_spawn(ioc, coro(), boost::asio::detached);
    ioc.run();
}
