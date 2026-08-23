/**
 * @file RacerIntegration.cpp
 * @brief Happy Eyeballs 真并发集成测试（5 场景）
 * @details 驱动方式：co_spawn + 完成回调捕获 exception_ptr + ioc.run()
 *          （MuxLifecycle 模式），异常透传至测试主体，禁止 run_for/poll。
 */

#include <gtest/gtest.h>

#include <prism/net/connection/dialer/racer.hpp>
#include <prism/net/transport/reliable.hpp>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <utility>
#include <vector>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using psm::connect::address_racer;
    using psm::connect::shared_transmission;

    /// 驱动协程直至完成（异常透传）
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

    /// 构造立即成功的拨号结果（未连接的可靠传输桩）
    auto ok_result(net::any_io_executor ex)
        -> std::pair<psm::fault::code, shared_transmission>
    {
        auto tr = std::make_shared<psm::transport::reliable>(tcp::socket(std::move(ex)));
        return {psm::fault::code::success, std::move(tr)};
    }

    /// 挂起指定时长后返回失败的拨号协程（被取消时抛 operation_aborted，由 racer 捕获）
    auto fail_after(net::any_io_executor ex, std::chrono::milliseconds delay)
        -> net::awaitable<std::pair<psm::fault::code, shared_transmission>>
    {
        net::steady_timer t(std::move(ex));
        t.expires_after(delay);
        co_await t.async_wait(net::use_awaitable);
        co_return std::pair{psm::fault::code::connection_refused, shared_transmission{}};
    }
}

TEST(RacerIntegration, SingleEndpointImmediateSuccess)
{
    net::io_context ioc;
    auto body = [&]() -> net::awaitable<void>
    {
        int dial_count = 0;
        address_racer racer(
            [&](const tcp::endpoint &) -> net::awaitable<std::pair<psm::fault::code, shared_transmission>>
            {
                ++dial_count;
                co_return ok_result(ioc.get_executor());
            });
        const std::array<tcp::endpoint, 1> eps{tcp::endpoint(net::ip::make_address("127.0.0.1"), 12345)};
        const auto res = co_await racer.race(eps);
        EXPECT_NE(res, nullptr);
        EXPECT_EQ(dial_count, 1);
    };
    run_coro(ioc, body());
}

TEST(RacerIntegration, FirstWinsSecondCancelled)
{
    net::io_context ioc;
    auto body = [&]() -> net::awaitable<void>
    {
        address_racer racer(
            [&](const tcp::endpoint &ep) -> net::awaitable<std::pair<psm::fault::code, shared_transmission>>
            {
                if (ep.port() == 1111)
                {
                    co_return ok_result(ioc.get_executor());
                }
                // 第二个延迟 500ms 后成功，但应被取消，不得拖慢整体返回
                co_return co_await fail_after(ioc.get_executor(), std::chrono::milliseconds(500));
            });
        const std::array<tcp::endpoint, 2> eps{
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 1111),
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 2222)};
        const auto start = std::chrono::steady_clock::now();
        const auto res = co_await racer.race(eps);
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        EXPECT_NE(res, nullptr);
        EXPECT_LT(elapsed, 400); // 快速返回，不等 500ms 失败者
    };
    run_coro(ioc, body());
}

TEST(RacerIntegration, FirstFailsSecondSucceeds)
{
    net::io_context ioc;
    auto body = [&]() -> net::awaitable<void>
    {
        address_racer racer(
            [&](const tcp::endpoint &ep) -> net::awaitable<std::pair<psm::fault::code, shared_transmission>>
            {
                if (ep.port() == 1111)
                {
                    co_return std::pair{psm::fault::code::connection_refused, shared_transmission{}};
                }
                co_return ok_result(ioc.get_executor());
            });
        const std::array<tcp::endpoint, 2> eps{
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 1111),
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 2222)};
        const auto res = co_await racer.race(eps);
        EXPECT_NE(res, nullptr);
    };
    run_coro(ioc, body());
}

TEST(RacerIntegration, AllFailReturnsNull)
{
    net::io_context ioc;
    auto body = [&]() -> net::awaitable<void>
    {
        address_racer racer(
            [&](const tcp::endpoint &) -> net::awaitable<std::pair<psm::fault::code, shared_transmission>>
            {
                co_return std::pair{psm::fault::code::connection_refused, shared_transmission{}};
            });
        const std::array<tcp::endpoint, 2> eps{
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 1111),
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 2222)};
        const auto res = co_await racer.race(eps);
        EXPECT_EQ(res, nullptr);
    };
    run_coro(ioc, body());
}

TEST(RacerIntegration, Staggered250ms)
{
    net::io_context ioc;
    auto body = [&]() -> net::awaitable<void>
    {
        std::vector<std::chrono::steady_clock::time_point> starts;
        address_racer racer(
            [&](const tcp::endpoint &) -> net::awaitable<std::pair<psm::fault::code, shared_transmission>>
            {
                starts.push_back(std::chrono::steady_clock::now());
                // 全部挂起 400ms 后失败，让竞速器走完整个阶梯
                co_return co_await fail_after(ioc.get_executor(), std::chrono::milliseconds(400));
            });
        const std::array<tcp::endpoint, 3> eps{
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 1111),
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 2222),
            tcp::endpoint(net::ip::make_address("127.0.0.1"), 3333)};
        const auto res = co_await racer.race(eps);
        EXPECT_EQ(res, nullptr);
        // 验证 250ms 阶梯：至少两次启动（协程内禁 ASSERT_*，用 EXPECT + 守卫）
        EXPECT_GE(starts.size(), 2U);
        if (starts.size() >= 2U)
        {
            const auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  starts[1] - starts[0])
                                  .count();
            EXPECT_GE(diff, 200);
            EXPECT_LE(diff, 400);
        }
    };
    run_coro(ioc, body());
}
