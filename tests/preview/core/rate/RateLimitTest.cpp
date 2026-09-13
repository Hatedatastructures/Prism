/**
 * @file RateLimitTest.cpp
 * @brief 限速/封禁测试（T5-4 O4）
 * @details 覆盖：
 *          - 令牌桶：容量 / 补发 / 突发 / 并发不超发
 *          - throttle 中间件：不足 → blocked
 *          - Ban 中间件：阈值封禁 + 窗口过期解封
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <thread>
#include <vector>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Runtime/Middleware/Builtin/Throttle.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Foundation/Utility/Rate/TokenBucket.hpp>

namespace
{

    namespace Net = boost::asio;

    std::uint64_t FakeMilliseconds = 0;
    auto FakeClock() -> std::uint64_t
    {
        return FakeMilliseconds;
    }

    TEST(TokenBucket, CapacityLimit)
    {
        Preview::Rate::TokenBucket Bucket(3, std::chrono::milliseconds(100), 1);
        EXPECT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_FALSE(Bucket.TryTake(1, 0)); // 容量耗尽
        EXPECT_FALSE(Bucket.TryTake(2, 0));
    }

    TEST(TokenBucket, RefillOverTime)
    {
        Preview::Rate::TokenBucket Bucket(5, std::chrono::milliseconds(100), 2);
        EXPECT_TRUE(Bucket.TryTake(5, 0));  // 取满
        EXPECT_FALSE(Bucket.TryTake(1, 50)); // 未到间隔

        EXPECT_TRUE(Bucket.TryTake(2, 100)); // 100ms 补 2
        EXPECT_FALSE(Bucket.TryTake(1, 150)); // 还差 50ms
        EXPECT_TRUE(Bucket.TryTake(2, 200)); // 再补 2
        EXPECT_EQ(Bucket.Available(), 0);
    }

    TEST(TokenBucket, BurstConsumption)
    {
        Preview::Rate::TokenBucket Bucket(10, std::chrono::milliseconds(50), 1);
        // 突发取 10（桶满）
        EXPECT_TRUE(Bucket.TryTake(10, 0));
        EXPECT_FALSE(Bucket.TryTake(1, 0));
        // 长时间后补发封顶于容量
        EXPECT_TRUE(Bucket.TryTake(10, 100000)); // 补发大量但封顶
        EXPECT_EQ(Bucket.Available(), 0);
    }

    TEST(TokenBucket, SaturatesTimestampAtUint64Maximum)
    {
        Preview::Rate::TokenBucket Bucket(1, std::chrono::milliseconds(1), 1);

        ASSERT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(1, std::numeric_limits<std::uint64_t>::max()));
    }

    TEST(TokenBucket, SaturatesRefillArithmeticAtPackedTokenLimit)
    {
        constexpr auto Capacity = std::numeric_limits<std::uint32_t>::max();
        Preview::Rate::TokenBucket Bucket(
            Capacity, std::chrono::milliseconds(1), std::numeric_limits<std::size_t>::max());

        ASSERT_TRUE(Bucket.TryTake(1, 0));
        EXPECT_TRUE(Bucket.TryTake(Capacity, 1));
        EXPECT_EQ(Bucket.Available(), 0u);
    }

    TEST(TokenBucket, ConcurrentNoOverdraw)
    {
        Preview::Rate::TokenBucket Bucket(1000, std::chrono::milliseconds(1000), 100);
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
        Preview::Rate::TokenBucket Bucket(2, std::chrono::milliseconds(100), 1);
        Preview::Middleware::Builtin::ThrottleMiddleware Throttle(&Bucket, FakeClock);

        Preview::Middleware::Context Context;
        Preview::SharedTransmission Inbound;

        Preview::Fault::Code Result1 = Preview::Fault::Code::Success;
        Preview::Fault::Code Result2 = Preview::Fault::Code::Success;
        Preview::Fault::Code Result3 = Preview::Fault::Code::Success;
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
        EXPECT_EQ(Result1, Preview::Fault::Code::Success);
        EXPECT_EQ(Result2, Preview::Fault::Code::Success);
        EXPECT_EQ(Result3, Preview::Fault::Code::Blocked);
    }

    TEST(BanMiddleware, ThresholdBans)
    {
        FakeMilliseconds = 0;
        Preview::Middleware::Builtin::BanMiddleware Ban(3, 1000, FakeClock);

        Ban.RecordFailure("1.2.3.4");
        Ban.RecordFailure("1.2.3.4");
        EXPECT_FALSE(Ban.IsBanned("1.2.3.4"));
        Ban.RecordFailure("1.2.3.4"); // 达阈值
        EXPECT_TRUE(Ban.IsBanned("1.2.3.4"));

        // 其他键不受影响
        EXPECT_FALSE(Ban.IsBanned("5.6.7.8"));
    }

    TEST(BanMiddleware, WindowExpiryUnbans)
    {
        FakeMilliseconds = 0;
        Preview::Middleware::Builtin::BanMiddleware Ban(2, 1000, FakeClock);

        Ban.RecordFailure("host");
        Ban.RecordFailure("host");
        EXPECT_TRUE(Ban.IsBanned("host"));

        FakeMilliseconds = 1500; // 窗口过期
        EXPECT_FALSE(Ban.IsBanned("host"));
    }

    TEST(BanMiddleware, HandleBlocksWhenBanned)
    {
        Net::io_context IoContext;
        FakeMilliseconds = 0;
        Preview::Middleware::Builtin::BanMiddleware Ban(1, 1000, FakeClock);
        Ban.RecordFailure("offender");

        Preview::Middleware::Context Context;
        Context.RawIdentity = "offender";
        Preview::SharedTransmission Inbound;

        Preview::Fault::Code ResultCode = Preview::Fault::Code::Success;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void> { ResultCode = co_await Ban.Handle(Inbound, Context); },
                      [&](std::exception_ptr ExceptionValue) { Exception = ExceptionValue; IoContext.stop(); });
        IoContext.run();
        ASSERT_FALSE(Exception);
        EXPECT_EQ(ResultCode, Preview::Fault::Code::Blocked);
    }

} // namespace
