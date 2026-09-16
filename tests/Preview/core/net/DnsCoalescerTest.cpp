/**
 * @file DnsCoalescerTest.cpp
 * @brief DNS single-flight 合并层测试
 * @details 覆盖：FindCreate 同键复用、leader 完成唤醒等待者、
 *          两阶段清理生命周期、活跃等待者阻止清理
 */

#include <Preview/Net/Dns/Coalescer.hpp>

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
    namespace Net = boost::asio;
    using Preview::Network::Dns::Coalescer;
    using Preview::Network::Dns::Flight;

    using TestResult = std::vector<Net::ip::address>;
} // namespace

TEST(DnsCoalescer, TestFindCreateReusesFlight)
{
    Net::io_context ioc;
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
    Net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight, isNew] = c.FindCreate("wake.com", 1);
    ASSERT_TRUE(isNew);

    bool waiterGotResult = false;
    bool waiterSawValue = false;
    boost::system::error_code waitEc;

    auto waiter = [&]() -> Net::awaitable<void>
    {
        flight->AcquireWaiter();
        co_await flight->Timer().async_wait(
            Net::redirect_error(Net::use_awaitable, waitEc));
        flight->ReleaseWaiter();
        if (const auto *res = c.GetResult(*flight))
        {
            waiterGotResult = true;
            waiterSawValue = !res->empty();
        }
    };
    Net::co_spawn(ioc, waiter, Net::detached);

    // leader 延迟完成后写入结果并唤醒
    auto leader = [&]() -> Net::awaitable<void>
    {
        Net::steady_timer delay(ioc.get_executor());
        delay.expires_after(std::chrono::milliseconds(20));
        co_await delay.async_wait(Net::use_awaitable);
        c.SetResult(flight, TestResult{Net::ip::make_address("5.5.5.5")});
        c.CleanupFlight(flight);
    };
    Net::co_spawn(ioc, leader, Net::detached);

    ioc.run();

    // 等待者被 cancel 唤醒（而非超时）且读到结果
    EXPECT_EQ(waitEc, Net::error::operation_aborted);
    EXPECT_TRUE(waiterGotResult);
    EXPECT_TRUE(waiterSawValue);
    EXPECT_EQ(flight->Ready(), true);
}

TEST(DnsCoalescer, TestCleanupLifecycle)
{
    Net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight, isNew] = c.FindCreate("life.com", 1);
    ASSERT_TRUE(isNew);

    // 未完成时清理不生效
    c.CleanupFlight(flight);
    EXPECT_FALSE(flight->PendingCleanup());
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 1u);

    // 完成后标记 + 两阶段删除（flight 与结果槽一起移除）
    c.SetResult(flight, TestResult{Net::ip::make_address("6.6.6.6")});
    c.CleanupFlight(flight);
    EXPECT_TRUE(flight->PendingCleanup());
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 0u);
    EXPECT_EQ(c.GetResult(*flight), nullptr);
}

TEST(DnsCoalescer, TestActiveWaiterBlocksCleanup)
{
    Net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight, isNew] = c.FindCreate("busy.com", 1);
    ASSERT_TRUE(isNew);

    flight->AcquireWaiter();
    c.SetResult(flight, TestResult{});
    c.CleanupFlight(flight);
    // 有等待者 → 不标记待清理，Flush 不删除
    EXPECT_FALSE(flight->PendingCleanup());
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 1u);

    // 等待者离开后可正常清理
    flight->ReleaseWaiter();
    c.CleanupFlight(flight);
    c.FlushCleanup();
    EXPECT_EQ(c.Size(), 0u);
}

TEST(DnsCoalescer, TestConcurrentWaitersSingleFlight)
{
    // 多等待者并发挂在同一 flight：leader 完成一次即全部唤醒，
    // 每位等待者都读到同一结果（single-flight 语义）
    Net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    auto [flight, isNew] = c.FindCreate("burst.com", 1);
    ASSERT_TRUE(isNew);

    constexpr int WaiterCount = 8;
    int woke = 0;
    std::vector<TestResult> seen(WaiterCount);

    auto waiter = [&](const int id) -> Net::awaitable<void>
    {
        flight->AcquireWaiter();
        boost::system::error_code waitEc;
        co_await flight->Timer().async_wait(
            Net::redirect_error(Net::use_awaitable, waitEc));
        flight->ReleaseWaiter();
        if (const auto *res = c.GetResult(*flight))
        {
            seen[static_cast<std::size_t>(id)] = *res;
            ++woke;
        }
    };
    for (int i = 0; i < WaiterCount; ++i)
    {
        Net::co_spawn(ioc, waiter(i), Net::detached);
    }

    // leader 延迟完成后一次性唤醒所有等待者
    auto leader = [&]() -> Net::awaitable<void>
    {
        Net::steady_timer delay(ioc.get_executor());
        delay.expires_after(std::chrono::milliseconds(20));
        co_await delay.async_wait(Net::use_awaitable);
        c.SetResult(flight, TestResult{Net::ip::make_address("7.7.7.7")});
        c.CleanupFlight(flight);
    };
    Net::co_spawn(ioc, leader, Net::detached);

    ioc.run();

    EXPECT_EQ(woke, WaiterCount);
    for (int i = 1; i < WaiterCount; ++i)
    {
        ASSERT_EQ(seen[static_cast<std::size_t>(i)].size(), 1u);
        EXPECT_EQ(seen[static_cast<std::size_t>(i)][0], seen[0][0]);
    }
    EXPECT_EQ(flight->Waiters(), 0u);
    EXPECT_TRUE(flight->Ready());
}
