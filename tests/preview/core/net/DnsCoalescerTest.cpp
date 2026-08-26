/**
 * @file DnsCoalescerTest.cpp
 * @brief DNS single-flight 合并层测试
 * @details 覆盖：FindCreate 同键复用、leader 完成唤醒等待者、
 *          两阶段清理生命周期、活跃等待者阻止清理
 */

#include <common/Core/Net/Dns/Coalescer.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>

#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;
    using Preview::Network::Dns::Coalescer;
    using Preview::Network::Dns::Flight;

    using TestResult = std::vector<net::ip::address>;
} // namespace

TEST(DnsCoalescer, TestFindCreateReusesFlight)
{
    net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight1, isNew1] = c.FindCreate("a.com", 1);
    ASSERT_TRUE(isNew1);
    EXPECT_EQ(flight1->Key(), "a.com:1");

    auto [flight2, isNew2] = c.FindCreate("a.com", 1);
    EXPECT_FALSE(isNew2);
    EXPECT_EQ(flight1, flight2);

    // 不同键不同 flight
    auto [flight3, isNew3] = c.FindCreate("a.com", 28);
    EXPECT_TRUE(isNew3);
    EXPECT_NE(flight1, flight3);
    EXPECT_EQ(c.Size(), 2u);
}

TEST(DnsCoalescer, TestLeaderWakesWaiter)
{
    net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight, isNew] = c.FindCreate("wake.com", 1);
    ASSERT_TRUE(isNew);

    bool waiterGotResult = false;
    bool waiterSawValue = false;
    boost::system::error_code waitEc;

    auto waiter = [&]() -> net::awaitable<void>
    {
        flight->AddWaiter(+1);
        co_await flight->Timer().async_wait(
            net::redirect_error(net::use_awaitable, waitEc));
        flight->AddWaiter(-1);
        if (const auto *res = c.GetResult(*flight))
        {
            waiterGotResult = true;
            waiterSawValue = !res->empty();
        }
    };
    net::co_spawn(ioc, waiter, net::detached);

    // leader 延迟完成后写入结果并唤醒
    auto leader = [&]() -> net::awaitable<void>
    {
        net::steady_timer delay(ioc.get_executor());
        delay.expires_after(std::chrono::milliseconds(20));
        co_await delay.async_wait(net::use_awaitable);
        c.SetResult(flight, TestResult{net::ip::make_address("5.5.5.5")});
        c.CleanupFlight(flight);
    };
    net::co_spawn(ioc, leader, net::detached);

    ioc.run();

    // 等待者被 cancel 唤醒（而非超时）且读到结果
    EXPECT_EQ(waitEc, net::error::operation_aborted);
    EXPECT_TRUE(waiterGotResult);
    EXPECT_TRUE(waiterSawValue);
    EXPECT_EQ(flight->Ready(), true);
}

TEST(DnsCoalescer, TestCleanupLifecycle)
{
    net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight, isNew] = c.FindCreate("life.com", 1);
    ASSERT_TRUE(isNew);

    // 未完成时清理不生效
    c.CleanupFlight(flight);
    EXPECT_FALSE(flight->PendingCleanup());
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 1u);

    // 完成后标记 + 两阶段删除（flight 与结果槽一起移除）
    c.SetResult(flight, TestResult{net::ip::make_address("6.6.6.6")});
    c.CleanupFlight(flight);
    EXPECT_TRUE(flight->PendingCleanup());
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 0u);
    EXPECT_EQ(c.GetResult(*flight), nullptr);
}

TEST(DnsCoalescer, TestActiveWaiterBlocksCleanup)
{
    net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight, isNew] = c.FindCreate("busy.com", 1);
    ASSERT_TRUE(isNew);

    flight->AddWaiter(+1);
    c.SetResult(flight, TestResult{});
    c.CleanupFlight(flight);
    // 有等待者 → 不标记待清理，Flush 不删除
    EXPECT_FALSE(flight->PendingCleanup());
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 1u);

    // 等待者离开后可正常清理
    flight->AddWaiter(-1);
    c.CleanupFlight(flight);
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 0u);
}
