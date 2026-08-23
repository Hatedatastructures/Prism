/**
 * @file TrafficMiddlewareTest.cpp
 * @brief 流量统计聚合测试（T4-4）
 * @details 覆盖：
 *          - 按 identity 聚合 up/down
 *          - 未知 identity / 零流量返回 0
 *          - 多会话累计（同一 identity 汇总）
 *          - 会话编排集成：relay 结束点 → 聚合器收到
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>

#include <common/core/authenticator.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/runtime/statistics.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transmission.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace preview;

    using psm::testing::run_coro; // 公共样板（见 <common/RuntimeTestHelpers.hpp>）

    /// 回显上游
    auto echo_upstream(shared_transmission client_side) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        while (true)
        {
            const auto n = co_await client_side->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                break;
            }
            co_await client_side->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
            if (ec)
            {
                break;
            }
        }
        client_side->close();
    }

    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<memory_stream>, std::shared_ptr<memory_stream>>
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        return {std::make_shared<memory_stream>(std::move(a)),
                std::make_shared<memory_stream>(std::move(b))};
    }

    TEST(TrafficCounter, AggregateByIdentity)
    {
        preview::runtime::traffic_counter counter;
        counter.report("alice", 10, 20);
        counter.report("alice", 5, 7);
        counter.report("bob", 100, 1);

        auto a = counter.total("alice");
        EXPECT_EQ(a.up, 15);
        EXPECT_EQ(a.down, 27);
        auto b = counter.total("bob");
        EXPECT_EQ(b.up, 100);
        EXPECT_EQ(b.down, 1);
        EXPECT_EQ(counter.identity_count(), 2);

        auto g = counter.grand_total();
        EXPECT_EQ(g.up, 115);
        EXPECT_EQ(g.down, 28);
    }

    TEST(TrafficCounter, UnknownIdentityZero)
    {
        preview::runtime::traffic_counter counter;
        auto e = counter.total("nobody");
        EXPECT_EQ(e.up, 0);
        EXPECT_EQ(e.down, 0);
        EXPECT_EQ(counter.identity_count(), 0);
    }

    TEST(TrafficCounter, EmptyIdentityAggregates)
    {
        preview::runtime::traffic_counter counter;
        counter.report("", 3, 4);
        counter.report("", 2, 1);
        auto e = counter.total("");
        EXPECT_EQ(e.up, 5);
        EXPECT_EQ(e.down, 5);
        EXPECT_EQ(counter.identity_count(), 1);
    }

    TEST(TrafficCounter, SessionPipelineIntegration)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        preview::runtime::traffic_counter counter;
        preview::runtime::session_options opts;
        opts.auth = std::make_shared<preview::static_authenticator>("alice", "pw");
        opts.traffic = &counter;
        opts.relay_idle_timeout = std::chrono::milliseconds(50);
        opts.prepare = [](const preview::recognition::recognize_result &,
                          preview::middleware::context &ctx) -> net::awaitable<preview::fault::code>
        {
            ctx.target.positive = true;
            ctx.raw_identity = "alice";
            ctx.raw_secret = "pw";
            co_return preview::fault::code::success;
        };
        opts.dial = [outbound_s](const preview::network::target &) -> net::awaitable<
            std::pair<preview::fault::code, preview::shared_transmission>>
        {
            co_return std::pair{preview::fault::code::success, outbound_s};
        };
        preview::runtime::session session(opts);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await session.run(inbound_s); },
                         net::detached);
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await echo_upstream(upstream_s); },
                         net::detached);

                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     std::array<std::byte, 64> buf{};
                     std::error_code sec;
                     const auto n = co_await client_s->async_read_some(std::span<std::byte>(buf), sec);
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), payload);

                     // 空闲超时 → relay 结束 → 上报
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(300));
                     co_await t.async_wait(net::use_awaitable);
                     client_s->close();
                 });

        auto a = counter.total("alice");
        EXPECT_GE(a.up, socks5_greeting().size()); // 上行：首包
        EXPECT_GE(a.down, socks5_greeting().size()); // 下行：回显
        EXPECT_EQ(counter.identity_count(), 1);
    }

} // namespace
