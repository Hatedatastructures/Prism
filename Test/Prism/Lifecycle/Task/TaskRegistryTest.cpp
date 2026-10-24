/**
 * @file TaskRegistryTest.cpp
 * @brief Lifecycle TaskRegistry 的真实任务、取消和析构边界测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <expected>
#include <limits>
#include <memory>
#include <optional>

#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Lifecycle/TaskRetirementReceipt.hpp>
#include <TestSupport/Fixtures/TaskRegistryAccess.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Lifecycle = Prism::Lifecycle;

    [[nodiscard]] auto MakeIdentity(const std::uint64_t Value) -> Lifecycle::TaskIdentity
    {
        return Lifecycle::TaskIdentity{
            .TaskId = Prism::TaskId{Value},
            .SessionId = Prism::SessionId{Value},
            .StreamId = Prism::StreamId{Value},
            .WorkerId = Prism::WorkerId{Value},
            .Generation = Prism::GenerationId{Value}};
    }

    [[nodiscard]] auto MakeRequest(const std::uint64_t Value,
                                   Lifecycle::TaskCancelFn Cancel = {}) -> Lifecycle::TaskRequest
    {
        const auto Identity = MakeIdentity(Value);
        return Lifecycle::TaskRequest{
            Lifecycle::TaskContext{
                Identity.SessionId,
                Identity.StreamId,
                Identity.WorkerId,
                Identity.Generation,
                {}},
            std::move(Cancel),
            true};
    }

    auto CompleteTask() -> Net::awaitable<void>
    {
        co_return;
    }

    auto Increment(std::shared_ptr<std::atomic<int>> Counter) -> Net::awaitable<void>
    {
        ++*Counter;
        co_return;
    }

    auto WaitForCancellation(
        std::shared_ptr<Net::steady_timer> Timer,
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Started)
        -> Net::awaitable<void>
    {
        (void)Started->try_send(boost::system::error_code{});
        Timer->expires_after(std::chrono::hours(24));
        boost::system::error_code Error;
        co_await Timer->async_wait(Net::redirect_error(Net::use_awaitable, Error));
    }

    using TaskSignal = Net::experimental::channel<void(boost::system::error_code)>;

    struct TaskRetirementScenario final
    {
        std::shared_ptr<TaskSignal> Started;
        std::shared_ptr<TaskSignal> Release;
        bool WorkCompleted{false};
        bool ReceiptReady{false};
        bool ReceiptFailed{false};
        bool CancelAccepted{false};
        bool ReleaseSent{false};
        bool RetiredBeforeRelease{false};
        bool ExactIdentityFound{false};
        bool WrongIdentityFound{false};
        bool ScopeDrained{false};
        std::size_t ActiveBeforeRelease{0};
    };

    auto WaitForExplicitRelease(
        std::shared_ptr<TaskRetirementScenario> Scenario) -> Net::awaitable<void>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        (void)Scenario->Started->try_send(boost::system::error_code{});
        boost::system::error_code Error;
        co_await Scenario->Release->async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        Scenario->WorkCompleted = !Error;
    }

    auto ObserveRetirement(
        Lifecycle::TaskHandle Task,
        std::shared_ptr<TaskRetirementScenario> Scenario) -> Net::awaitable<void>
    {
        const auto Result = co_await Task.WaitForRetirementAsync();
        Scenario->ReceiptReady = Result.has_value();
        Scenario->ReceiptFailed = !Result;
    }

    struct CancelTaskScenarioRequest final
    {
        Net::io_context &Io;
        Lifecycle::TaskRegistry &Registry;
        std::shared_ptr<Lifecycle::TaskRegistry> Scope;
        Lifecycle::TaskHandle Task;
        std::shared_ptr<TaskRetirementScenario> Scenario;
    };

    auto CancelAndReleaseTask(CancelTaskScenarioRequest Request) -> Net::awaitable<void>
    {
        co_await Request.Scenario->Started->async_receive(Net::use_awaitable);
        auto Found = co_await Request.Registry.FindTask(Request.Task.Identity());
        Request.Scenario->ExactIdentityFound = Found && Found->has_value();
        auto WrongIdentity = Request.Task.Identity();
        WrongIdentity.StreamId = Prism::StreamId{WrongIdentity.StreamId.Value() + 1U};
        auto Wrong = co_await Request.Registry.FindTask(WrongIdentity);
        Request.Scenario->WrongIdentityFound = Wrong && Wrong->has_value();
        Request.Scenario->CancelAccepted = Request.Registry.Cancel();
        co_await Net::post(Request.Io, Net::use_awaitable);
        Request.Scenario->RetiredBeforeRelease = Request.Scenario->ReceiptReady;
        Request.Scenario->ActiveBeforeRelease = Request.Registry.Stats().Active;
        Request.Scenario->ReleaseSent = Request.Scenario->Release->try_send(
            boost::system::error_code{});
        const auto Drained = co_await Request.Scope->Drain();
        Request.Scenario->ScopeDrained = Drained.has_value();
    }

    class NextTaskIdGuard final
    {
    public:
        explicit NextTaskIdGuard(const std::uint64_t Seed)
            : Saved_(Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(Seed))
        {
        }

        ~NextTaskIdGuard()
        {
            (void)Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(Saved_);
        }

    private:
        std::uint64_t Saved_;
    };

    TEST(TaskRegistry, SpawnTrackedCompletes)
    {
        Net::io_context IoContext;
        Lifecycle::TaskRegistry Registry(IoContext.get_executor());
        auto Ran = std::make_shared<std::atomic<int>>(0);

        const auto Task = Registry.SpawnTracked(
            MakeRequest(1), Increment(Ran));
        ASSERT_TRUE(Task);
        IoContext.run();

        EXPECT_EQ(Ran->load(), 1);
        const auto Stats = Registry.Stats();
        EXPECT_EQ(Stats.Started, 1U);
        EXPECT_EQ(Stats.Completed, 1U);
        EXPECT_EQ(Stats.Active, 0U);
    }

    TEST(TaskRegistry, CancelAndDrainCleansPendingTask)
    {
        Net::io_context IoContext;
        Lifecycle::TaskRegistry Registry(IoContext.get_executor());
        auto Timer = std::make_shared<Net::steady_timer>(IoContext);
        auto Started = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            IoContext.get_executor(), 1);
        auto Canceled = std::make_shared<std::atomic<int>>(0);
        bool Drained = false;
        std::exception_ptr Failure;

        const auto Task = Registry.SpawnTracked(
            MakeRequest(2, [Timer, Canceled]
            {
                ++*Canceled;
                Timer->cancel();
            }),
            WaitForCancellation(Timer, Started));
        ASSERT_TRUE(Task);

        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                co_await Started->async_receive(Net::use_awaitable);
                (void)Registry.Cancel();
                const auto Result = co_await Registry.Drain();
                Drained = Result.has_value();
            },
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        IoContext.run();

        ASSERT_FALSE(Failure);
        EXPECT_TRUE(Drained);
        EXPECT_EQ(Canceled->load(), 1);
        EXPECT_EQ(Registry.Stats().Cancelled, 1U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
    }

    TEST(TaskRegistry, SealRejectsNewTasksAndDrainCompletesPublishedTask)
    {
        Net::io_context IoContext;
        Lifecycle::TaskRegistry Registry(IoContext.get_executor());
        auto Ran = std::make_shared<std::atomic<int>>(0);
        const auto Task = Registry.SpawnTracked(
            MakeRequest(3), Increment(Ran));
        ASSERT_TRUE(Task);
        Registry.Seal();

        const auto Rejected = Registry.SpawnTracked(
            MakeRequest(4), CompleteTask());
        EXPECT_FALSE(Rejected);

        bool Drained = false;
        std::exception_ptr Failure;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                const auto Result = co_await Registry.Drain();
                Drained = Result.has_value();
            },
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        IoContext.run();

        ASSERT_FALSE(Failure);
        EXPECT_TRUE(Drained);
        EXPECT_EQ(Ran->load(), 1);
        EXPECT_EQ(Registry.Stats().Active, 0U);
    }

    TEST(TaskRegistry, DestructionQuarantinesQueuedTaskWithoutOwnerCallback)
    {
        Net::io_context IoContext;
        std::optional<Lifecycle::TaskHandle> Task;
        {
            Lifecycle::TaskRegistry Registry(IoContext.get_executor());
            auto Submitted = Registry.SpawnTracked(
                MakeRequest(5), CompleteTask());
            ASSERT_TRUE(Submitted);
            Task.emplace(std::move(*Submitted));
        }

        IoContext.run();
        ASSERT_TRUE(Task.has_value());
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->Result().Outcome, Lifecycle::TaskOutcome::Quarantined);
    }

    TEST(TaskRegistry, RetirementReceiptWaitsForCancellationIgnoringRunToExit)
    {
        Net::io_context IoContext;
        Lifecycle::TaskRegistry Registry(IoContext.get_executor());
        auto Scope = Registry.CreateChild();
        auto Scenario = std::make_shared<TaskRetirementScenario>();
        Scenario->Started = std::make_shared<TaskSignal>(IoContext.get_executor(), 1U);
        Scenario->Release = std::make_shared<TaskSignal>(IoContext.get_executor(), 1U);
        auto Task = Scope->SpawnTracked(MakeRequest(6), WaitForExplicitRelease(Scenario));
        ASSERT_TRUE(Task);
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, ObserveRetirement(*Task, Scenario),
            [&Failure](std::exception_ptr Error)
            { if (Error) Failure = std::move(Error); });
        Net::co_spawn(IoContext,
            CancelAndReleaseTask(CancelTaskScenarioRequest{
                IoContext, Registry, Scope, *Task, Scenario}),
            [&Failure](std::exception_ptr Error)
            { if (Error) Failure = std::move(Error); });

        IoContext.run();

        ASSERT_FALSE(Failure);
        EXPECT_TRUE(Scenario->CancelAccepted);
        EXPECT_TRUE(Scenario->ReleaseSent);
        EXPECT_FALSE(Scenario->RetiredBeforeRelease);
        EXPECT_TRUE(Scenario->ExactIdentityFound);
        EXPECT_FALSE(Scenario->WrongIdentityFound);
        EXPECT_TRUE(Scenario->ScopeDrained);
        EXPECT_EQ(Scenario->ActiveBeforeRelease, 1U);
        EXPECT_TRUE(Scenario->WorkCompleted);
        EXPECT_TRUE(Scenario->ReceiptReady);
        EXPECT_FALSE(Scenario->ReceiptFailed);
        const auto Observation = Task->Observation();
        EXPECT_EQ(Observation.Result.Outcome, Lifecycle::TaskOutcome::Cancelled);
        EXPECT_GT(Observation.StartedAt, 0U);
        EXPECT_GE(Observation.CompletedAt, Observation.StartedAt);
        EXPECT_EQ(Registry.Stats().Active, 0U);
    }

    TEST(TaskRetirementReceipt, WaitPinsOwnerBeforeCoroutineStarts)
    {
        using Outcome = std::expected<void, Prism::Fault::Failure>;
        Net::io_context IoContext;
        auto Receipt = std::make_shared<Lifecycle::TaskRetirementReceipt>();
        auto Waiting = Receipt->WaitAsync();
        Receipt->Publish();
        Receipt.reset();
        std::optional<Outcome> Result;
        std::exception_ptr Failure;

        Net::co_spawn(IoContext, std::move(Waiting),
            [&Result, &Failure](std::exception_ptr Error, Outcome Value)
            {
                Failure = std::move(Error);
                if (!Failure) Result = std::move(Value);
            });
        IoContext.run();

        ASSERT_FALSE(Failure);
        ASSERT_TRUE(Result.has_value());
        EXPECT_TRUE(Result->has_value());
    }

    /**
     * @brief 验证 owner 分配器在最大值、耗尽和任务释放边界上的单调行为。
     * @details 生产接口不再接受调用方指定 TaskId；测试 friend 只注入边界种子，
     *          并由 guard 恢复全局分配序列，不构成兼容入口。
     */
    TEST(TaskRegistry, AutomaticIdSkipsRetainedReservationAfterMaximumIsReleased)
    {
        Net::io_context IoContext;
        NextTaskIdGuard IdGuard{1U};
        Lifecycle::TaskRegistry Registry(IoContext.get_executor());
        const auto First = Registry.SpawnTracked(MakeRequest(1), CompleteTask());
        ASSERT_TRUE(First);
        IoContext.run();
        ASSERT_TRUE(First->IsCompleted());
        ASSERT_EQ(Registry.Stats().Active, 0U);

        IoContext.restart();
        Lifecycle::TaskRegistry Automatic(IoContext.get_executor());
        {
            (void)Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(
                (std::numeric_limits<std::uint64_t>::max)());
            Lifecycle::TaskRegistry Upper(IoContext.get_executor());
            const auto Last = Upper.SpawnTracked(
                MakeRequest((std::numeric_limits<std::uint64_t>::max)()), CompleteTask());
            ASSERT_TRUE(Last);
            IoContext.run();
            ASSERT_TRUE(Last->IsCompleted());
            ASSERT_EQ(Upper.Stats().Active, 0U);
            IoContext.restart();
            EXPECT_FALSE(Automatic.SpawnTracked(MakeRequest(0), CompleteTask()));
        }

        EXPECT_FALSE(Automatic.SpawnTracked(MakeRequest(1), CompleteTask()));
        (void)Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(2U);
        const auto Reused = Automatic.SpawnTracked(MakeRequest(0), CompleteTask());
        ASSERT_TRUE(Reused);
        EXPECT_EQ(Reused->Identity().TaskId, Prism::TaskId{2});
        IoContext.restart();
        IoContext.run();
        EXPECT_TRUE(Reused->IsCompleted());
        EXPECT_EQ(Reused->CompletionCount(), 1U);
        EXPECT_EQ(Automatic.Stats().Active, 0U);
        EXPECT_EQ(Automatic.Stats().Completed, 1U);
    }

    /**
     * @brief 故意销毁未驱动域，确认丢失任务阻断而不向已关闭 channel 投递。
     * @details 本例检验不可恢复的域销毁边界，故意不运行已排队的任务；
     *          共享通知许可必须变成不可用，不能把任务冒称为已完成。
     */
    TEST(TaskRegistry, ContextTeardownDisablesLateDrainNotifications)
    {
        std::shared_ptr<const std::atomic<bool>> Notification;
        {
            Net::io_context IoContext;
            Lifecycle::TaskRegistry Registry(IoContext.get_executor());
            const auto Queued = Registry.SpawnTracked(MakeRequest(1), CompleteTask());
            ASSERT_TRUE(Queued);
            Notification = Lifecycle::BindDrainNotification(IoContext.get_executor());
            EXPECT_TRUE(Notification->load(std::memory_order_acquire));
            EXPECT_EQ(Registry.Stats().Active, 1U);
            EXPECT_FALSE(Queued->IsCompleted());
        }
        ASSERT_TRUE(Notification);
        EXPECT_FALSE(Notification->load(std::memory_order_acquire));
    }

} // namespace
