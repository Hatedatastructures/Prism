/**
 * @file RegistryTest.cpp
 * @brief 协程注册表测试（coroutine/Registry）
 * @details 覆盖：
 *          - SpawnTracked 正常完成 → token 释放 + 计数
 *          - 多协程统计计数（spawned/released/Active）
 *          - CancelAndWait 清算路径（cancelled 计数 + 清空）
 *          - Registry 析构解除 token 绑定（不悬垂）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <string>

#include <Preview/Foundation/Utility/Coroutine/Registry.hpp>

namespace
{

    namespace Net = boost::asio;

    TEST(TaskRegistry, SpawnTrackedCompletes)
    {
        Net::io_context IoContext;
        Preview::Coroutine::TaskRegistry Registry(IoContext);

        std::atomic<int> Ran{0};
        Registry.SpawnTracked("complete", [&]() -> Net::awaitable<void>
                               { ++Ran; co_return; });
        IoContext.run();

        EXPECT_EQ(Ran, 1);
        const auto Stats = Registry.Stats();
        EXPECT_EQ(Stats.TotalSpawned, 1);
        EXPECT_EQ(Stats.TotalReleased, 1);
        EXPECT_EQ(Stats.Active, 0);
    }

    TEST(TaskRegistry, StatsCounters)
    {
        Net::io_context IoContext;
        Preview::Coroutine::TaskRegistry Registry(IoContext);

        for (int Index = 0; Index < 5; ++Index)
        {
            Registry.SpawnTracked("task-" + std::to_string(Index),
                                   [Index]() -> Net::awaitable<void>
                                   {
                                       (void)Index;
                                       co_return;
                                   });
        }
        EXPECT_EQ(Registry.Stats().TotalSpawned, 5);
        EXPECT_EQ(Registry.Stats().Active, 5); // Run 前活跃

        IoContext.run();
        const auto Stats = Registry.Stats();
        EXPECT_EQ(Stats.TotalSpawned, 5);
        EXPECT_EQ(Stats.TotalReleased, 5);
        EXPECT_EQ(Stats.Active, 0);
    }

    TEST(TaskRegistry, CancelAndWaitCleans)
    {
        Net::io_context IoContext;
        Preview::Coroutine::TaskRegistry Registry(IoContext);

        std::atomic<int> Started{0};
        std::atomic<int> Canceled{0};
        for (int Index = 0; Index < 2; ++Index)
        {
            Registry.SpawnTracked("pending", [&IoContext, &Started, &Canceled]() -> Net::awaitable<void>
                                   {
                                       ++Started;
                                       Net::steady_timer Timer(IoContext);
                                       Timer.expires_after(std::chrono::hours(24));
                                       boost::system::error_code ErrorCode;
                                       co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
                                       if (ErrorCode == Net::error::operation_aborted)
                                       {
                                           ++Canceled;
                                       }
                                       co_return;
                                   });
        }

        bool Result = false;
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                while (Started.load() != 2)
                {
                    Net::steady_timer Timer(IoContext);
                    Timer.expires_after(std::chrono::milliseconds(1));
                    co_await Timer.async_wait(Net::use_awaitable);
                }
                Result = co_await Registry.CancelAndWait(std::chrono::milliseconds(100));
            },
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
            });
        IoContext.run();

        ASSERT_FALSE(Exception);
        EXPECT_TRUE(Result);
        const auto Stats = Registry.Stats();
        EXPECT_EQ(Stats.TotalSpawned, 2);
        EXPECT_EQ(Stats.TotalCancelled, 2);
        EXPECT_EQ(Stats.Active, 0);
        EXPECT_EQ(Canceled, 2);
    }

    TEST(TaskRegistry, CancelAndWaitTimesOutWithoutDroppingToken)
    {
        Net::io_context IoContext;
        Preview::Coroutine::TaskRegistry Registry(IoContext);
        auto Timer = std::make_shared<Net::steady_timer>(IoContext);

        Registry.SpawnTracked("non-cancellable", [Timer]() -> Net::awaitable<void>
                               {
                                   Timer->expires_after(std::chrono::seconds(5));
                                   boost::system::error_code ErrorCode;
                                   auto Completion = Net::redirect_error(Net::use_awaitable, ErrorCode);
                                   co_await Timer->async_wait(
                                       Net::bind_cancellation_slot(Net::cancellation_slot{}, Completion));
                                   co_return;
                               });

        bool Result = true;
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Registry.CancelAndWait(std::chrono::milliseconds(5));
            },
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
                IoContext.stop();
            });
        IoContext.run();

        ASSERT_FALSE(Exception);
        EXPECT_FALSE(Result);
        EXPECT_EQ(Registry.Stats().Active, 1);
        EXPECT_EQ(Registry.Stats().TotalCancelled, 0);

        Timer->cancel();
        IoContext.restart();
        IoContext.run();
        EXPECT_EQ(Registry.Stats().Active, 0);
        EXPECT_EQ(Registry.Stats().TotalCancelled, 1);
    }

    TEST(TaskRegistry, DestroyDetachesTokens)
    {
        Net::io_context IoContext;
        {
            Preview::Coroutine::TaskRegistry Registry(IoContext);
            Registry.SpawnTracked("orphan", []() -> Net::awaitable<void>
                                   { co_return; });
        } // 析构：解除 token 绑定，无悬垂（不崩溃即通过）
        IoContext.run();
        SUCCEED();
    }

    TEST(TaskRegistry, MixedCompleteAndPending)
    {
        Net::io_context IoContext;
        Preview::Coroutine::TaskRegistry Registry(IoContext);

        std::atomic<int> Ran{0};
        Registry.SpawnTracked("Done", [&]() -> Net::awaitable<void>
                               { ++Ran; co_return; });
        // pending：挂起在超长 Timer 上（Run 后 token 仍活跃；析构安全）
        Registry.SpawnTracked("pending", [&]() -> Net::awaitable<void>
                               {
            Net::steady_timer Timer(IoContext);
            Timer.expires_after(std::chrono::hours(24));
            co_await Timer.async_wait(Net::use_awaitable);
        });

        // 驱动 100ms：Done 完成，pending 仍挂起（run_for 保证返回）
        IoContext.run_for(std::chrono::milliseconds(100));
        EXPECT_EQ(Ran, 1);
        EXPECT_EQ(Registry.Stats().TotalReleased, 1);
        EXPECT_EQ(Registry.Stats().Active, 1);

        // 清算残留；取消必须让挂起的 Timer 收口后再返回。
        bool Result = false;
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Registry.CancelAndWait(std::chrono::milliseconds(100));
            },
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
            });
        IoContext.run();

        ASSERT_FALSE(Exception);
        EXPECT_TRUE(Result);
        EXPECT_EQ(Registry.Stats().TotalCancelled, 1);
        EXPECT_EQ(Registry.Stats().Active, 0);
    }

} // namespace
