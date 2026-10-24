/**
 * @file DnsCoalescerTest.cpp
 * @brief DNS single-flight 合并层测试
 * @details 覆盖：FindCreate 同键复用、leader 完成唤醒等待者、
 *          两阶段清理生命周期、活跃等待者阻止清理
 */

#include <Prism/Net/Dns/Coalescer.hpp>

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
    using Prism::Network::Dns::Coalescer;
    using Prism::Network::Dns::Flight;

    using TestResult = std::vector<Net::ip::address>;

    struct LeaderWakeWaiterRequest final
    {
        Coalescer<TestResult>::FlightPtr Flight;
        Coalescer<TestResult> &Owner;
        boost::system::error_code &WaitError;
        bool &GotResult;
        bool &SawValue;
    };

    /**
     * @brief 等待 leader 完成并读取共享 flight 结果。
     * @param Request 当前 flight、合并器和等待结果槽。
     * @return 等待通知并完成 waiter 计数更新的异步操作。
     * @details flight 由 shared_ptr 持有，结果和错误槽由同步运行该测试的调用方持有。
     */
    auto RunLeaderWakeWaiter(LeaderWakeWaiterRequest Request) -> Net::awaitable<void>
    {
        const auto Registered = Request.Flight->TryAcquireWaiter();
        EXPECT_TRUE(Registered);
        co_await Request.Flight->Timer().async_wait(
            Net::redirect_error(Net::use_awaitable, Request.WaitError));
        Request.Flight->ReleaseWaiter();
        if (const auto Result = Request.Owner.GetResult(*Request.Flight))
        {
            Request.GotResult = true;
            Request.SawValue = !Result->empty();
        }
    }

    struct ConcurrentWaiterRequest final
    {
        Coalescer<TestResult>::FlightPtr Flight;
        Coalescer<TestResult> &Owner;
        int Id;
        std::vector<TestResult> &Results;
        int &Woke;
    };

    /**
     * @brief 等待并发 single-flight 的共享结果。
     * @param Request 当前 waiter 的 flight、索引和结果槽。
     * @return 完成等待、计数和结果复制的异步操作。
     * @details 每个 waiter 保留自己的索引，所有 waiter 读取同一个已完成 flight。
     */
    auto RunConcurrentWaiter(ConcurrentWaiterRequest Request) -> Net::awaitable<void>
    {
        const auto Registered = Request.Flight->TryAcquireWaiter();
        EXPECT_TRUE(Registered);
        boost::system::error_code WaitError;
        co_await Request.Flight->Timer().async_wait(
            Net::redirect_error(Net::use_awaitable, WaitError));
        Request.Flight->ReleaseWaiter();
        if (const auto Result = Request.Owner.GetResult(*Request.Flight))
        {
            Request.Results[static_cast<std::size_t>(Request.Id)] = *Result;
            ++Request.Woke;
        }
    }
} // namespace

TEST(DnsCoalescer, TestFindCreateReusesFlight)
{
    Net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    const auto Lookup1 = c.FindCreate("a.com", 1);
    ASSERT_TRUE(Lookup1.has_value());
    ASSERT_TRUE(Lookup1->IsNew);
    const auto &flight1 = Lookup1->Flight;
    EXPECT_EQ(flight1->Key(), "a.com:1");

    const auto Lookup2 = c.FindCreate("a.com", 1);
    ASSERT_TRUE(Lookup2.has_value());
    EXPECT_FALSE(Lookup2->IsNew);
    EXPECT_EQ(flight1, Lookup2->Flight);

    // 不同键不同 flight
    const auto Lookup3 = c.FindCreate("a.com", 28);
    ASSERT_TRUE(Lookup3.has_value());
    EXPECT_TRUE(Lookup3->IsNew);
    EXPECT_NE(flight1, Lookup3->Flight);
    EXPECT_EQ(c.Size(), 2u);
}

TEST(DnsCoalescer, TestLeaderWakesWaiter)
{
    Net::io_context ioc;
    Coalescer<TestResult> c(ioc.get_executor());

    const auto Lookup = c.FindCreate("wake.com", 1);
    ASSERT_TRUE(Lookup.has_value());
    ASSERT_TRUE(Lookup->IsNew);
    const auto &flight = Lookup->Flight;

    bool waiterGotResult = false;
    bool waiterSawValue = false;
    boost::system::error_code waitEc;

    Net::co_spawn(
        ioc,
        RunLeaderWakeWaiter(
            LeaderWakeWaiterRequest{flight, c, waitEc, waiterGotResult, waiterSawValue}),
        Net::detached);

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

    const auto Lookup = c.FindCreate("life.com", 1);
    ASSERT_TRUE(Lookup.has_value());
    ASSERT_TRUE(Lookup->IsNew);
    const auto &flight = Lookup->Flight;

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

    const auto Lookup = c.FindCreate("busy.com", 1);
    ASSERT_TRUE(Lookup.has_value());
    ASSERT_TRUE(Lookup->IsNew);
    const auto &flight = Lookup->Flight;

    EXPECT_TRUE(flight->TryAcquireWaiter());
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

    const auto Lookup = c.FindCreate("burst.com", 1);
    ASSERT_TRUE(Lookup.has_value());
    ASSERT_TRUE(Lookup->IsNew);
    const auto &flight = Lookup->Flight;

    constexpr int WaiterCount = 8;
    int woke = 0;
    std::vector<TestResult> seen(WaiterCount);

    for (int i = 0; i < WaiterCount; ++i)
    {
        Net::co_spawn(
            ioc,
            RunConcurrentWaiter(
                ConcurrentWaiterRequest{flight, c, i, seen, woke}),
            Net::detached);
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
