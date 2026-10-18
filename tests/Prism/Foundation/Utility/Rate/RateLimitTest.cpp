/**
 * @file RateLimitTest.cpp
 * @brief 限速/封禁测试（T5-4 O4）
 * @details 覆盖：
 *          - 令牌桶：容量 / 补发 / 突发 / 并发不超发
 *          - throttle 中间件：不足 → blocked
 *          - Ban 中间件：阈值封禁 + 窗口过期解封
 */

#include <gtest/gtest.h>

#include <barrier>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <thread>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/Middleware/Builtin/Throttle.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Foundation/Utility/Rate/TokenBucket.hpp>

namespace
{

    namespace Net = boost::asio;

    std::uint64_t FakeMilliseconds = 0;
    auto FakeClock() -> std::uint64_t
    {
        return FakeMilliseconds;
    }

    auto RunFailure(Net::io_context &IoContext,
        Net::awaitable<Prism::Fault::Failure> Operation) -> Prism::Fault::Failure
    {
        Prism::Fault::Failure Result;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Operation),
            [&Result, &Exception](std::exception_ptr Error, Prism::Fault::Failure Value)
            {
                Exception = std::move(Error);
                if (!Exception) Result = std::move(Value);
            });
        IoContext.run();
        IoContext.restart();
        if (Exception) std::rethrow_exception(Exception);
        return Result;
    }

    TEST(TokenBucket, CapacityLimit)
    {
        Prism::Rate::TokenBucket Bucket(3, std::chrono::milliseconds(100), 1);
        EXPECT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_FALSE(Bucket.TryTake(1, 0)); // 容量耗尽
        EXPECT_FALSE(Bucket.TryTake(2, 0));
    }

    TEST(TokenBucket, RefillOverTime)
    {
        Prism::Rate::TokenBucket Bucket(5, std::chrono::milliseconds(100), 2);
        EXPECT_TRUE(Bucket.TryTake(5, 0));  // 取满
        EXPECT_FALSE(Bucket.TryTake(1, 50)); // 未到间隔

        EXPECT_TRUE(Bucket.TryTake(2, 100)); // 100ms 补 2
        EXPECT_FALSE(Bucket.TryTake(1, 150)); // 还差 50ms
        EXPECT_TRUE(Bucket.TryTake(2, 200)); // 再补 2
        EXPECT_EQ(Bucket.Available(), 0);
    }

    TEST(TokenBucket, BurstConsumption)
    {
        Prism::Rate::TokenBucket Bucket(10, std::chrono::milliseconds(50), 1);
        // 突发取 10（桶满）
        EXPECT_TRUE(Bucket.TryTake(10, 0));
        EXPECT_FALSE(Bucket.TryTake(1, 0));
        // 长时间后补发封顶于容量
        EXPECT_TRUE(Bucket.TryTake(10, 100000)); // 补发大量但封顶
        EXPECT_EQ(Bucket.Available(), 0);
    }

    TEST(TokenBucket, SaturatesTimestampAtUint64Maximum)
    {
        Prism::Rate::TokenBucket Bucket(1, std::chrono::milliseconds(1), 1);

        ASSERT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(1, std::numeric_limits<std::uint64_t>::max()));
    }

    TEST(TokenBucket, UsesFirstTryTakeTimestampAsRefillEpoch)
    {
        Prism::Rate::TokenBucket Bucket(1, std::chrono::milliseconds(100), 1);

        ASSERT_TRUE(Bucket.TryTake(1, 150));
        EXPECT_FALSE(Bucket.TryTake(1, 200));
        EXPECT_TRUE(Bucket.TryTake(1, 250));
    }

    TEST(TokenBucket, DoesNotRepeatRefillAtSameTimestampAfterUint32RelativeTime)
    {
        Prism::Rate::TokenBucket Bucket(1, std::chrono::milliseconds(100), 1);

        ASSERT_TRUE(Bucket.TryTake(1, 0));
        constexpr auto CrossedNow = std::uint64_t{0xFFFFFFFF} + 1000;
        ASSERT_TRUE(Bucket.TryTake(1, CrossedNow));
        EXPECT_FALSE(Bucket.TryTake(1, CrossedNow));
        EXPECT_EQ(Bucket.Available(), 0u);
    }

    TEST(TokenBucket, RefillResumesAfterLongIdleBeyondUint32RelativeTime)
    {
        Prism::Rate::TokenBucket Bucket(3, std::chrono::milliseconds(100), 1);

        ASSERT_TRUE(Bucket.TryTake(3, 0));
        constexpr auto LongIdleNow = std::uint64_t{0xFFFFFFFF} + 5;
        ASSERT_TRUE(Bucket.TryTake(3, LongIdleNow));
        EXPECT_EQ(Bucket.Available(), 0u);

        EXPECT_TRUE(Bucket.TryTake(1, LongIdleNow + 100));
        EXPECT_EQ(Bucket.Available(), 0u);
    }

    TEST(TokenBucket, ConcurrentNoOverdrawAfterUint32RelativeTime)
    {
        constexpr std::size_t Capacity = 4;
        constexpr int ThreadCount = 16;
        Prism::Rate::TokenBucket Bucket(Capacity, std::chrono::milliseconds(100), 1);

        ASSERT_TRUE(Bucket.TryTake(Capacity, 0));
        constexpr auto CrossedNow = std::uint64_t{0xFFFFFFFF} + 1000;
        std::barrier StartGate(static_cast<std::ptrdiff_t>(ThreadCount));
        std::atomic<int> Successful{0};
        std::vector<std::thread> ThreadPool;
        ThreadPool.reserve(ThreadCount);
        for (int ThreadIndex = 0; ThreadIndex < ThreadCount; ++ThreadIndex)
        {
            ThreadPool.emplace_back([&]()
                                    {
                                        StartGate.arrive_and_wait();
                                        if (Bucket.TryTake(1, CrossedNow))
                                        {
                                            Successful.fetch_add(1, std::memory_order_relaxed);
                                        }
                                    });
        }
        for (auto &Thread : ThreadPool)
        {
            Thread.join();
        }

        EXPECT_EQ(Successful.load(std::memory_order_relaxed), static_cast<int>(Capacity));
        EXPECT_EQ(Bucket.Available(), 0u);
    }

    TEST(TokenBucket, InsufficientRefillDoesNotOverwriteConcurrentConsumption)
    {
        constexpr std::size_t Capacity = 8;
        constexpr std::size_t CycleCount = 1024;
        constexpr std::size_t RefillCount = 1;
        constexpr std::size_t InsufficientThreadCount = 8;
        constexpr auto InitialNow = std::uint64_t{0};
        Prism::Rate::TokenBucket Bucket(Capacity, std::chrono::milliseconds(1), RefillCount);

        ASSERT_TRUE(Bucket.TryTake(Capacity, InitialNow));
        // 每轮只补发一个令牌；消费者可能错过某轮，令牌留到下一轮后 Count=2 合法成功。
        // 只用加权消耗、末余量和总补发预算判断，不把某个角色的成功次数当作固定调度结果。
        std::atomic<std::uint64_t> CurrentNow{InitialNow};
        std::atomic<std::size_t> SuccessfulTokens{0};
        std::atomic<std::size_t> SuccessfulInsufficientCalls{0};
        std::atomic<std::size_t> SuccessfulConsumerCalls{0};
        const auto ParticipantCount =
            static_cast<std::ptrdiff_t>(InsufficientThreadCount + 2);
        std::barrier StartGate(ParticipantCount);
        std::barrier EndGate(ParticipantCount);

        auto RunInsufficientWorker = [&]()
        {
            for (std::size_t Cycle = 1; Cycle <= CycleCount; ++Cycle)
            {
                StartGate.arrive_and_wait();
                if (Bucket.TryTake(2, CurrentNow.load(std::memory_order_relaxed)))
                {
                    SuccessfulTokens.fetch_add(2, std::memory_order_relaxed);
                    SuccessfulInsufficientCalls.fetch_add(1, std::memory_order_relaxed);
                }
                EndGate.arrive_and_wait();
            }
        };
        auto RunConsumer = [&]()
        {
            for (std::size_t Cycle = 1; Cycle <= CycleCount; ++Cycle)
            {
                StartGate.arrive_and_wait();
                if (Bucket.TryTake(1, CurrentNow.load(std::memory_order_relaxed)))
                {
                    SuccessfulTokens.fetch_add(1, std::memory_order_relaxed);
                    SuccessfulConsumerCalls.fetch_add(1, std::memory_order_relaxed);
                }
                EndGate.arrive_and_wait();
            }
        };

        std::vector<std::thread> InsufficientThreads;
        InsufficientThreads.reserve(InsufficientThreadCount);
        for (std::size_t Index = 0; Index < InsufficientThreadCount; ++Index)
        {
            InsufficientThreads.emplace_back(RunInsufficientWorker);
        }
        std::thread Consumer(RunConsumer);

        for (std::size_t Cycle = 1; Cycle <= CycleCount; ++Cycle)
        {
            CurrentNow.store(static_cast<std::uint64_t>(Cycle), std::memory_order_relaxed);
            StartGate.arrive_and_wait();
            EndGate.arrive_and_wait();
        }

        Consumer.join();
        for (auto &Thread : InsufficientThreads)
        {
            Thread.join();
        }

        const auto ConsumedTokens = SuccessfulTokens.load(std::memory_order_relaxed);
        const auto SuccessfulInsufficient =
            SuccessfulInsufficientCalls.load(std::memory_order_relaxed);
        const auto SuccessfulConsumers = SuccessfulConsumerCalls.load(std::memory_order_relaxed);
        const auto RemainingTokens = Bucket.Available();
        const auto RefillBudget = CycleCount * RefillCount;
        EXPECT_EQ(ConsumedTokens, SuccessfulConsumers + SuccessfulInsufficient * 2);
        EXPECT_LE(SuccessfulConsumers, CycleCount);
        EXPECT_LE(ConsumedTokens, RefillBudget);
        EXPECT_LE(RemainingTokens, RefillBudget);
        EXPECT_LE(ConsumedTokens + RemainingTokens, RefillBudget);
    }

    TEST(TokenBucket, SaturatesRefillArithmeticAtPackedTokenLimit)
    {
        constexpr auto Capacity = std::numeric_limits<std::uint32_t>::max();
        Prism::Rate::TokenBucket Bucket(
            Capacity, std::chrono::milliseconds(1), std::numeric_limits<std::size_t>::max());

        ASSERT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(Capacity, 1));
        EXPECT_EQ(Bucket.Available(), 0u);
    }

    TEST(TokenBucket, ConcurrentNoOverdraw)
    {
        Prism::Rate::TokenBucket Bucket(1000, std::chrono::milliseconds(1000), 100);
        // 400 线程并发各取 1：应只允许 1000 个
        constexpr int ThreadCount = 8;
        constexpr int PerThread = 200; // 共 1600 次尝试 > 容量 1000
        std::atomic<int> Ok{0};
        std::vector<std::thread> ThreadPool;
        for (int ThreadIndex = 0; ThreadIndex < ThreadCount; ++ThreadIndex)
        {
            ThreadPool.emplace_back([&]()
                              {
                for (int Index = 0; Index < PerThread; ++Index)
                {
                    if (Bucket.TryTake(1, 0))
                    {
                        ++Ok;
                    }
                } });
        }
        for (auto &Thread : ThreadPool)
        {
            Thread.join();
        }
        EXPECT_EQ(Ok, 1000); // 恰好容量，无超发
    }

    TEST(ThrottleMiddleware, BlockedWhenExhausted)
    {
        Net::io_context IoContext;
        Prism::Rate::TokenBucket Bucket(2, std::chrono::milliseconds(100), 1);
        Prism::Middleware::Builtin::ThrottleMiddleware Throttle(&Bucket, FakeClock);

        Prism::Middleware::Context Context;
        Prism::SharedTransmission Inbound;

        Prism::Fault::Failure Result1;
        Prism::Fault::Failure Result2;
        Prism::Fault::Failure Result3;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext,
                      [&]() -> Net::awaitable<void>
                      {
                          Result1 = co_await Throttle.Handle(Inbound, Context);
                          Result2 = co_await Throttle.Handle(Inbound, Context);
                          Result3 = co_await Throttle.Handle(Inbound, Context);
                      },
                      [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        ASSERT_FALSE(Exception);
        EXPECT_EQ(Result1.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Result2.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Result3.Code, Prism::Fault::Code::Blocked);
    }

    TEST(BanMiddleware, ThresholdBans)
    {
        Net::io_context IoContext;
        Prism::Middleware::Builtin::BanMiddleware Ban(
            Prism::Middleware::Builtin::BanOptions{3, 1000}, IoContext.get_executor());
        Prism::Middleware::Context Context;
        Prism::SharedTransmission Inbound;
        Context.SourceIp = "1.2.3.4";

        EXPECT_EQ(RunFailure(IoContext, Ban.RecordFailure(Context.SourceIp)).Code,
            Prism::Fault::Code::Success);
        EXPECT_EQ(RunFailure(IoContext, Ban.RecordFailure(Context.SourceIp)).Code,
            Prism::Fault::Code::Success);
        EXPECT_EQ(RunFailure(IoContext, Ban.Handle(Inbound, Context)).Code,
            Prism::Fault::Code::Success);
        EXPECT_EQ(RunFailure(IoContext, Ban.RecordFailure(Context.SourceIp)).Code,
            Prism::Fault::Code::Success); // 达阈值
        EXPECT_EQ(RunFailure(IoContext, Ban.Handle(Inbound, Context)).Code,
            Prism::Fault::Code::Blocked);

        // 其他键不受影响
        Context.SourceIp = "5.6.7.8";
        EXPECT_EQ(RunFailure(IoContext, Ban.Handle(Inbound, Context)).Code,
            Prism::Fault::Code::Success);
    }

    TEST(BanMiddleware, WindowExpiryUnbans)
    {
        Net::io_context IoContext;
        Prism::Middleware::Builtin::BanMiddleware Ban(
            Prism::Middleware::Builtin::BanOptions{2, 1000}, IoContext.get_executor());
        Prism::Middleware::Context Context;
        Prism::SharedTransmission Inbound;
        Context.SourceIp = "host";

        EXPECT_EQ(RunFailure(IoContext, Ban.RecordFailure(Context.SourceIp)).Code,
            Prism::Fault::Code::Success);
        EXPECT_EQ(RunFailure(IoContext, Ban.RecordFailure(Context.SourceIp)).Code,
            Prism::Fault::Code::Success);
        EXPECT_EQ(RunFailure(IoContext, Ban.Handle(Inbound, Context)).Code,
            Prism::Fault::Code::Blocked);

        std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // 原 1000ms 窗口到期后验证解封。
        EXPECT_EQ(RunFailure(IoContext, Ban.Handle(Inbound, Context)).Code,
            Prism::Fault::Code::Success);
    }

    TEST(BanMiddleware, HandleBlocksWhenBanned)
    {
        Net::io_context IoContext;
        Prism::Middleware::Builtin::BanMiddleware Ban(
            Prism::Middleware::Builtin::BanOptions{1, 1000}, IoContext.get_executor());
        EXPECT_EQ(RunFailure(IoContext, Ban.RecordFailure("offender")).Code,
            Prism::Fault::Code::Success);

        Prism::Middleware::Context Context;
        Context.SourceIp = "offender";
        Prism::SharedTransmission Inbound;

        const auto Result = RunFailure(IoContext, Ban.Handle(Inbound, Context));
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Blocked);
    }

} // namespace
