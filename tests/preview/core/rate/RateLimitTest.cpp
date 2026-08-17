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

#include <common/core/fault/code.hpp>
#include <common/core/middleware/builtin/throttle.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/rate/token_bucket.hpp>

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
        preview::rate::token_bucket bucket(3, std::chrono::milliseconds(100), 1);
        EXPECT_TRUE(bucket.try_take(1, 0));
        EXPECT_TRUE(bucket.try_take(1, 0));
        EXPECT_TRUE(bucket.try_take(1, 0));
        EXPECT_FALSE(bucket.try_take(1, 0)); // 容量耗尽
        EXPECT_FALSE(bucket.try_take(2, 0));
    }

    TEST(TokenBucket, RefillOverTime)
    {
        preview::rate::token_bucket bucket(5, std::chrono::milliseconds(100), 2);
        EXPECT_TRUE(bucket.try_take(5, 0));  // 取满
        EXPECT_FALSE(bucket.try_take(1, 50)); // 未到间隔

        EXPECT_TRUE(bucket.try_take(2, 100)); // 100ms 补 2
        EXPECT_FALSE(bucket.try_take(1, 150)); // 还差 50ms
        EXPECT_TRUE(bucket.try_take(2, 200)); // 再补 2
        EXPECT_EQ(bucket.available(), 0);
    }

    TEST(TokenBucket, BurstConsumption)
    {
        preview::rate::token_bucket bucket(10, std::chrono::milliseconds(50), 1);
        // 突发取 10（桶满）
        EXPECT_TRUE(bucket.try_take(10, 0));
        EXPECT_FALSE(bucket.try_take(1, 0));
        // 长时间后补发封顶于容量
        EXPECT_TRUE(bucket.try_take(10, 100000)); // 补发大量但封顶
        EXPECT_EQ(bucket.available(), 0);
    }

    TEST(TokenBucket, ConcurrentNoOverdraw)
    {
        preview::rate::token_bucket bucket(1000, std::chrono::milliseconds(1000), 100);
        // 400 线程并发各取 1：应只允许 1000 个
        constexpr int threads = 8;
        constexpr int per_thread = 200; // 共 1600 次尝试 > 容量 1000
        std::atomic<int> ok{0};
        std::vector<std::thread> pool;
        for (int t = 0; t < threads; ++t)
        {
            pool.emplace_back([&]()
                              {
                for (int i = 0; i < per_thread; ++i)
                {
                    if (bucket.try_take(1, 0))
                    {
                        ++ok;
                    }
                } });
        }
        for (auto &th : pool)
        {
            th.join();
        }
        EXPECT_EQ(ok, 1000); // 恰好容量，无超发
    }

    TEST(ThrottleMiddleware, BlockedWhenExhausted)
    {
        net::io_context ioc;
        preview::rate::token_bucket bucket(2, std::chrono::milliseconds(100), 1);
        preview::middleware::builtin::throttle_middleware mw(&bucket, fake_clock);

        preview::middleware::context ctx;
        preview::shared_transmission inbound;

        preview::fault::code r1 = preview::fault::code::success;
        preview::fault::code r2 = preview::fault::code::success;
        preview::fault::code r3 = preview::fault::code::success;
        std::exception_ptr ep;
        net::co_spawn(ioc,
                      [&]() -> net::awaitable<void>
                      {
                          r1 = co_await mw.handle(inbound, ctx);
                          r2 = co_await mw.handle(inbound, ctx);
                          r3 = co_await mw.handle(inbound, ctx);
                      },
                      [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        ASSERT_FALSE(ep);
        EXPECT_EQ(r1, preview::fault::code::success);
        EXPECT_EQ(r2, preview::fault::code::success);
        EXPECT_EQ(r3, preview::fault::code::blocked);
    }

    TEST(BanMiddleware, ThresholdBans)
    {
        fake_ms = 0;
        preview::middleware::builtin::ban_middleware ban(3, 1000, fake_clock);

        ban.record_failure("1.2.3.4");
        ban.record_failure("1.2.3.4");
        EXPECT_FALSE(ban.is_banned("1.2.3.4"));
        ban.record_failure("1.2.3.4"); // 达阈值
        EXPECT_TRUE(ban.is_banned("1.2.3.4"));

        // 其他键不受影响
        EXPECT_FALSE(ban.is_banned("5.6.7.8"));
    }

    TEST(BanMiddleware, WindowExpiryUnbans)
    {
        fake_ms = 0;
        preview::middleware::builtin::ban_middleware ban(2, 1000, fake_clock);

        ban.record_failure("host");
        ban.record_failure("host");
        EXPECT_TRUE(ban.is_banned("host"));

        fake_ms = 1500; // 窗口过期
        EXPECT_FALSE(ban.is_banned("host"));
    }

    TEST(BanMiddleware, HandleBlocksWhenBanned)
    {
        net::io_context ioc;
        fake_ms = 0;
        preview::middleware::builtin::ban_middleware ban(1, 1000, fake_clock);
        ban.record_failure("offender");

        preview::middleware::context ctx;
        ctx.raw_identity = "offender";
        preview::shared_transmission inbound;

        preview::fault::code rc = preview::fault::code::success;
        std::exception_ptr ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void> { rc = co_await ban.handle(inbound, ctx); },
                      [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        ASSERT_FALSE(ep);
        EXPECT_EQ(rc, preview::fault::code::blocked);
    }

} // namespace
