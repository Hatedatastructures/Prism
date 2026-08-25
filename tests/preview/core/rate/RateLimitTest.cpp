/**
 * @file RateLimitTest.cpp
 * @brief 限速/封禁测试（T5-4 O4）
 * @details 覆盖：
 *          - 令牌桶：容量 / 补发 / 突发 / 并发不超发
 *          - throttle 中间件：不足 → blocked
 *          - ban 中间件：阈值封禁 + 窗口过期解封
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Middleware/Builtin/Throttle.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Rate/TokenBucket.hpp>

namespace
{

    namespace net = boost::asio;

    std::uint64_t fake_ms = 0;
    auto fake_clock() -> std::uint64_t
    {
        return fake_ms;
    }

    TEST(TokenBucket, CapacityLimit)
    {
        Preview::Rate::TokenBucket bucket(3, std::chrono::milliseconds(100), 1);
        EXPECT_TRUE(bucket.TryTake(1, 0));
        EXPECT_TRUE(bucket.TryTake(1, 0));
        EXPECT_TRUE(bucket.TryTake(1, 0));
        EXPECT_FALSE(bucket.TryTake(1, 0)); // 容量耗尽
        EXPECT_FALSE(bucket.TryTake(2, 0));
    }

    TEST(TokenBucket, RefillOverTime)
    {
        Preview::Rate::TokenBucket bucket(5, std::chrono::milliseconds(100), 2);
        EXPECT_TRUE(bucket.TryTake(5, 0));  // 取满
        EXPECT_FALSE(bucket.TryTake(1, 50)); // 未到间隔

        EXPECT_TRUE(bucket.TryTake(2, 100)); // 100ms 补 2
        EXPECT_FALSE(bucket.TryTake(1, 150)); // 还差 50ms
        EXPECT_TRUE(bucket.TryTake(2, 200)); // 再补 2
        EXPECT_EQ(bucket.Available(), 0);
    }

    TEST(TokenBucket, BurstConsumption)
    {
        Preview::Rate::TokenBucket bucket(10, std::chrono::milliseconds(50), 1);
        // 突发取 10（桶满）
        EXPECT_TRUE(bucket.TryTake(10, 0));
        EXPECT_FALSE(bucket.TryTake(1, 0));
        // 长时间后补发封顶于容量
        EXPECT_TRUE(bucket.TryTake(10, 100000)); // 补发大量但封顶
        EXPECT_EQ(bucket.Available(), 0);
    }

    TEST(TokenBucket, ConcurrentNoOverdraw)
    {
        Preview::Rate::TokenBucket bucket(1000, std::chrono::milliseconds(1000), 100);
        // 400 线程并发各取 1：应只允许 1000 个
        constexpr int threads = 8;
        constexpr int per_thread = 200; // 共 1600 次尝试 > 容量 1000
        std::atomic<int> Ok{0};
        std::vector<std::thread> pool;
        for (int t = 0; t < threads; ++t)
        {
            pool.emplace_back([&]()
                              {
                for (int i = 0; i < per_thread; ++i)
                {
                    if (bucket.TryTake(1, 0))
                    {
                        ++Ok;
                    }
                } });
        }
        for (auto &th : pool)
        {
            th.join();
        }
        EXPECT_EQ(Ok, 1000); // 恰好容量，无超发
    }

    TEST(ThrottleMiddleware, BlockedWhenExhausted)
    {
        net::io_context ioc;
        Preview::Rate::TokenBucket bucket(2, std::chrono::milliseconds(100), 1);
        Preview::Middleware::Builtin::ThrottleMiddleware mw(&bucket, fake_clock);

        Preview::Middleware::Context ctx;
        Preview::SharedTransmission inbound;

        Preview::Fault::Code r1 = Preview::Fault::Code::success;
        Preview::Fault::Code r2 = Preview::Fault::Code::success;
        Preview::Fault::Code r3 = Preview::Fault::Code::success;
        std::exception_ptr ep;
        net::co_spawn(ioc,
                      [&]() -> net::awaitable<void>
                      {
                          r1 = co_await mw.Handle(inbound, ctx);
                          r2 = co_await mw.Handle(inbound, ctx);
                          r3 = co_await mw.Handle(inbound, ctx);
                      },
                      [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        ASSERT_FALSE(ep);
        EXPECT_EQ(r1, Preview::Fault::Code::success);
        EXPECT_EQ(r2, Preview::Fault::Code::success);
        EXPECT_EQ(r3, Preview::Fault::Code::blocked);
    }

    TEST(BanMiddleware, ThresholdBans)
    {
        fake_ms = 0;
        Preview::Middleware::Builtin::BanMiddleware ban(3, 1000, fake_clock);

        ban.RecordFailure("1.2.3.4");
        ban.RecordFailure("1.2.3.4");
        EXPECT_FALSE(ban.IsBanned("1.2.3.4"));
        ban.RecordFailure("1.2.3.4"); // 达阈值
        EXPECT_TRUE(ban.IsBanned("1.2.3.4"));

        // 其他键不受影响
        EXPECT_FALSE(ban.IsBanned("5.6.7.8"));
    }

    TEST(BanMiddleware, WindowExpiryUnbans)
    {
        fake_ms = 0;
        Preview::Middleware::Builtin::BanMiddleware ban(2, 1000, fake_clock);

        ban.RecordFailure("host");
        ban.RecordFailure("host");
        EXPECT_TRUE(ban.IsBanned("host"));

        fake_ms = 1500; // 窗口过期
        EXPECT_FALSE(ban.IsBanned("host"));
    }

    TEST(BanMiddleware, HandleBlocksWhenBanned)
    {
        net::io_context ioc;
        fake_ms = 0;
        Preview::Middleware::Builtin::BanMiddleware ban(1, 1000, fake_clock);
        ban.RecordFailure("offender");

        Preview::Middleware::Context ctx;
        ctx.RawIdentity = "offender";
        Preview::SharedTransmission inbound;

        Preview::Fault::Code rc = Preview::Fault::Code::success;
        std::exception_ptr ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void> { rc = co_await ban.Handle(inbound, ctx); },
                      [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        ASSERT_FALSE(ep);
        EXPECT_EQ(rc, Preview::Fault::Code::blocked);
    }

} // namespace
