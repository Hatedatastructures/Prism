/**
 * @file TimeoutRelayTest.cpp
 * @brief 管线超时/背压测试（T4-5 / D9）
 * @details 覆盖：
 *          - 空闲超时关闭隧道（可配 + ctx.timeout 优先）
 *          - 持续活动不关闭
 *          - 0 = 禁用超时
 *          - 背压：写失败（对端关闭）→ 隧道立即终止
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

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/builtin/relay.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transmission.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace psmtest;

    auto run_coro(net::io_context &ioc, auto coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<memory_stream>, std::shared_ptr<memory_stream>>
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        return {std::make_shared<memory_stream>(std::move(a)),
                std::make_shared<memory_stream>(std::move(b))};
    }

    /// 运行 relay（构造参数超时），返回 handle 结果
    auto run_relay(net::io_context &ioc, std::shared_ptr<memory_stream> inbound,
                   std::shared_ptr<memory_stream> outbound, std::chrono::milliseconds timeout)
        -> psmtest::fault::code
    {
        psmtest::fault::code rc = psmtest::fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     psmtest::middleware::context ctx;
                     ctx.inbound = inbound;
                     ctx.outbound = outbound;
                     psmtest::middleware::builtin::relay_middleware relay(nullptr, timeout);
                     auto tmp = ctx.inbound;
                     rc = co_await relay.handle(tmp, ctx);
                 });
        return rc;
    }

    TEST(TimeoutRelay, IdleTimeoutClosesTunnel)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        // relay 结束标志
        bool relay_done = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             psmtest::middleware::context ctx;
                             ctx.inbound = a2;
                             ctx.outbound = b1;
                             psmtest::middleware::builtin::relay_middleware relay(nullptr,
                                                                                  std::chrono::milliseconds(50));
                             auto tmp = ctx.inbound;
                             co_await relay.handle(tmp, ctx);
                             relay_done = true;
                         },
                         net::detached);
                     // 无数据 → 50ms 空闲超时 → 关闭
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(300));
                     co_await t.async_wait(net::use_awaitable);
                     a1->close();
                 });
        EXPECT_TRUE(relay_done);
    }

    TEST(TimeoutRelay, NoTimeoutWhenActive)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool relay_done = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             psmtest::middleware::context ctx;
                             ctx.inbound = a2;
                             ctx.outbound = b1;
                             psmtest::middleware::builtin::relay_middleware relay(nullptr,
                                                                                  std::chrono::milliseconds(100));
                             auto tmp = ctx.inbound;
                             co_await relay.handle(tmp, ctx);
                             relay_done = true;
                         },
                         net::detached);

                     // 立即首包（relay 启动后马上有活动，避免初始超时窗口）
                     const std::string first = "first";
                     std::error_code wec;
                     co_await a1->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(first.data()),
                                                    first.size()),
                         wec);
                     std::array<std::byte, 64> buf{};
                     std::error_code rec;
                     const auto n0 = co_await b2->async_read_some(std::span<std::byte>(buf), rec);
                     EXPECT_GT(n0, 0);

                     // 持续活动（每 20ms 发一次，共 160ms > 超时 100ms）
                     for (int i = 0; i < 8; ++i)
                     {
                         const std::string msg = "keepalive-" + std::to_string(i);
                         co_await a1->async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()),
                                                        msg.size()),
                             wec);
                         const auto n = co_await b2->async_read_some(std::span<std::byte>(buf), rec);
                         EXPECT_GT(n, 0);
                         net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(20));
                         co_await t.async_wait(net::use_awaitable);
                     }
                     EXPECT_FALSE(relay_done); // 活动期间不关闭
                     a1->close();
                     // 给 relay 收尾时间
                     net::steady_timer t2(ioc);
                     t2.expires_after(std::chrono::milliseconds(100));
                     co_await t2.async_wait(net::use_awaitable);
                 });
        // 结束后 relay 才关闭
        EXPECT_TRUE(relay_done);
    }

    TEST(TimeoutRelay, ZeroDisablesTimeout)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool relay_done = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             psmtest::middleware::context ctx;
                             ctx.inbound = a2;
                             ctx.outbound = b1;
                             psmtest::middleware::builtin::relay_middleware relay(nullptr,
                                                                                  std::chrono::milliseconds(0));
                             auto tmp = ctx.inbound;
                             co_await relay.handle(tmp, ctx);
                             relay_done = true;
                         },
                         net::detached);
                     // 等 200ms（若超时未禁用，已关闭）
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(200));
                     co_await t.async_wait(net::use_awaitable);
                     EXPECT_FALSE(relay_done); // 0 = 禁用 → 未关闭
                     a1->close(); // 显式关闭才结束
                     net::steady_timer t2(ioc);
                     t2.expires_after(std::chrono::milliseconds(50));
                     co_await t2.async_wait(net::use_awaitable);
                 });
        EXPECT_TRUE(relay_done);
    }

    TEST(TimeoutRelay, ContextTimeoutTakesPriority)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool relay_done = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             psmtest::middleware::context ctx;
                             ctx.inbound = a2;
                             ctx.outbound = b1;
                             ctx.timeout = std::chrono::milliseconds(40); // ctx 优先（构造为 300s）
                             psmtest::middleware::builtin::relay_middleware relay(
                                 nullptr, std::chrono::seconds(300));
                             auto tmp = ctx.inbound;
                             co_await relay.handle(tmp, ctx);
                             relay_done = true;
                         },
                         net::detached);
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(300));
                     co_await t.async_wait(net::use_awaitable);
                     a1->close();
                 });
        EXPECT_TRUE(relay_done);
    }

    TEST(TimeoutRelay, WriteFailureTerminatesTunnel)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool relay_done = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             psmtest::middleware::context ctx;
                             ctx.inbound = a2;
                             ctx.outbound = b1;
                             psmtest::middleware::builtin::relay_middleware relay(
                                 nullptr, std::chrono::milliseconds(0));
                             auto tmp = ctx.inbound;
                             co_await relay.handle(tmp, ctx);
                             relay_done = true;
                         },
                         net::detached);

                     // 关闭 outbound 对端（b2）→ relay 写 b1 失败 → 隧道终止
                     b2->close();
                     const std::string msg = "to-dead-peer";
                     std::error_code wec;
                     co_await a1->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()),
                                                    msg.size()),
                         wec);
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(100));
                     co_await t.async_wait(net::use_awaitable);
                     a1->close();
                 });
        EXPECT_TRUE(relay_done);
    }

} // namespace
