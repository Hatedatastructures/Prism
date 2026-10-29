/**
 * @file RegistryDrainTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "LifecycleTestSupport.hpp"

#include <boost/asio/this_coro.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>

#include <cstddef>
#include <functional>
#include <thread>
#include <vector>

namespace
{
    /** @brief 确保测试提前返回时先停止 io_context，再 join 所有 runner。 */
    class IoThreadGroup final
    {
    public:
        explicit IoThreadGroup(Net::io_context &Io) noexcept
            : Io_(Io)
        {
        }

        ~IoThreadGroup() noexcept
        {
            Io_.stop();
            Join();
        }

        auto Start(const std::size_t Count) -> void
        {
            for (std::size_t Index = 0U; Index < Count; ++Index)
            {
                Threads_.emplace_back([this] { Io_.run(); });
            }
        }

        auto Join() noexcept -> void
        {
            for (auto &Thread : Threads_)
            {
                if (Thread.joinable())
                {
                    Thread.join();
                }
            }
        }

    private:
        Net::io_context &Io_;
        std::vector<std::thread> Threads_;
    };

    auto WaitForSignalAndMarkIgnoringCancellation(
        std::shared_ptr<Signal> Ready,
        std::shared_ptr<std::atomic<bool>> Started,
        std::shared_ptr<std::atomic<bool>> Completed) -> Net::awaitable<void>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        co_await WaitForSignalAndMark(std::move(Ready), std::move(Started), std::move(Completed));
    }

    /**
     * @brief 完成 First 子 registry 的 drain 回调。
     * @param Ready 该 drain 对应的等待槽。
     * @param Failure 协程 completion token 传回的异常。
     * @param Result typed drain 结果。
     */
    auto CompleteFirstDrain(
        std::promise<void> *Ready,
        std::exception_ptr Failure,
        std::expected<void, Prism::Fault::Failure> Result) -> void
    {
        EXPECT_FALSE(Failure);
        EXPECT_TRUE(Result);
        Ready->set_value();
    }

    /**
     * @brief 完成 Failed 子 registry 的 drain 回调。
     * @param Ready 该 drain 对应的等待槽。
     * @param Failure 协程 completion token 传回的异常。
     * @param Result typed drain 结果。
     */
    auto CompleteFailedDrain(
        std::promise<void> *Ready,
        std::exception_ptr Failure,
        std::expected<void, Prism::Fault::Failure> Result) -> void
    {
        EXPECT_FALSE(Failure);
        EXPECT_TRUE(Result);
        Ready->set_value();
    }

    /**
     * @brief 完成 Second 子 registry 的 drain 回调。
     * @param Ready 该 drain 对应的等待槽。
     * @param Failure 协程 completion token 传回的异常。
     * @param Result typed drain 结果。
     */
    auto CompleteSecondDrain(
        std::promise<void> *Ready,
        std::exception_ptr Failure,
        std::expected<void, Prism::Fault::Failure> Result) -> void
    {
        EXPECT_FALSE(Failure);
        EXPECT_TRUE(Result);
        Ready->set_value();
    }
} // namespace

TEST(TaskLifecycle, DrainCompletesBeforeRegistryRelease)
    {
        Net::io_context Ioc;
        auto Registry = std::make_unique<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        std::atomic<std::size_t> CancelCalls{0};
        auto Reclaimer = Registry->Reclaimer();

        auto Task = Registry->SpawnTracked(
            Request(
                Identity(),
                [&CancelCalls, Release]
                {
                    CancelCalls.fetch_add(1, std::memory_order_relaxed);
                    (void)Release->try_send(boost::system::error_code{});
                }),
            WaitForSignal(Release));
        ASSERT_TRUE(Task);

        (void)Registry->Cancel();
        const auto DrainResult = RunDrain(Ioc, Registry->Drain());
        ASSERT_TRUE(DrainResult);
        EXPECT_EQ(CancelCalls.load(std::memory_order_acquire), 1U);
        EXPECT_EQ(Registry->Stats().Active, 0U);
        EXPECT_EQ(Reclaimer->Pending(), 0U);
        Registry.reset();
        EXPECT_EQ(Reclaimer->Pending(), 0U);
    }

TEST(TaskLifecycle, DrainRemainsIncompleteBeforePendingTaskRelease)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        Prism::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Started = std::make_shared<std::atomic<bool>>(false);
        auto Completed = std::make_shared<std::atomic<bool>>(false);
        std::atomic<bool> DrainFailure{false};
        std::atomic<bool> DrainFinished{false};

        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            WaitForSignalAndMarkIgnoringCancellation(Release, Started, Completed));
        ASSERT_TRUE(Task);

        IoThreadGroup IoThreads(Ioc);
        IoThreads.Start(2U);
        while (!Started->load(std::memory_order_acquire))
        {
            Started->wait(false, std::memory_order_acquire);
        }

        (void)Registry.Cancel();
        auto DrainReady = std::make_shared<std::promise<void>>();
        auto DrainFuture = DrainReady->get_future();
        Net::co_spawn(
            Ioc,
            Registry.Drain(),
            [DrainReady, &DrainFailure, &DrainFinished](
                std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                DrainFailure.store(static_cast<bool>(Failure) || !Result, std::memory_order_release);
                DrainFinished.store(true, std::memory_order_release);
                DrainReady->set_value();
            });

        auto ObserverReady = std::make_shared<std::promise<void>>();
        auto ObserverFuture = ObserverReady->get_future();
        Net::post(Ioc, [ObserverReady] { ObserverReady->set_value(); });
        ASSERT_EQ(ObserverFuture.wait_for(std::chrono::seconds(1)), std::future_status::ready);
        EXPECT_FALSE(DrainFinished.load(std::memory_order_acquire));
        EXPECT_EQ(DrainFuture.wait_for(std::chrono::milliseconds(1)), std::future_status::timeout);

        ASSERT_TRUE(Release->try_send(boost::system::error_code{}));
        ASSERT_EQ(DrainFuture.wait_for(std::chrono::seconds(1)), std::future_status::ready);
        EXPECT_FALSE(DrainFailure.load(std::memory_order_acquire));
        EXPECT_TRUE(Completed->load(std::memory_order_acquire));
        EXPECT_EQ(Registry.Stats().Active, 0U);

        Work.reset();
        IoThreads.Join();
    }

TEST(TaskLifecycle, TeardownCancellationDispatchesOnMultiThreadExecutor)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto CancelReady = std::make_shared<std::promise<void>>();
        auto CancelFuture = CancelReady->get_future();
        auto Started = std::make_shared<std::atomic<bool>>(false);
        auto Completed = std::make_shared<std::atomic<bool>>(false);
        std::atomic<std::size_t> CancelCalls{0};
        std::optional<Prism::Lifecycle::TaskHandle> Task;
        IoThreadGroup IoThreads(Ioc);
        auto CancelStatus = std::future_status::timeout;

        {
            auto Registry = std::make_unique<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
            auto Submitted = Registry->SpawnTracked(
                Request(
                    Identity(),
                    [&CancelCalls, CancelReady, Release]
                    {
                        if (CancelCalls.fetch_add(1, std::memory_order_acq_rel) == 0)
                        {
                            CancelReady->set_value();
                        }
                        (void)Release->try_send(boost::system::error_code{});
                    }),
                WaitForSignalAndMark(Release, Started, Completed));
            ASSERT_TRUE(Submitted);
            Task.emplace(std::move(*Submitted));

            IoThreads.Start(2U);
            while (!Started->load(std::memory_order_acquire))
            {
                Started->wait(false, std::memory_order_acquire);
            }

            Registry.reset();
            CancelStatus = CancelFuture.wait_for(std::chrono::seconds(1));
            (void)Release->try_send(boost::system::error_code{});
            while (!Completed->load(std::memory_order_acquire))
            {
                Completed->wait(false, std::memory_order_acquire);
            }
            Work.reset();
            IoThreads.Join();
        }

        EXPECT_EQ(CancelStatus, std::future_status::ready);
        EXPECT_EQ(CancelCalls.load(std::memory_order_acquire), 1U);
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->CompletionCount(), 1U);
    }

TEST(TaskLifecycle, RegistryTeardownInvokesCancellationBeforeQuarantine)
    {
        Net::io_context Ioc;
        std::atomic<std::size_t> CancelCalls{0};
        std::optional<Prism::Lifecycle::TaskHandle> Task;

        {
            auto Registry = std::make_unique<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
            auto Submitted = Registry->SpawnTracked(
                Request(
                    Identity(),
                    [&CancelCalls] { CancelCalls.fetch_add(1, std::memory_order_relaxed); }),
                []() -> Net::awaitable<void> { co_return; }());
            ASSERT_TRUE(Submitted);
            Task.emplace(std::move(*Submitted));
        }

        Ioc.run();
        EXPECT_EQ(CancelCalls.load(std::memory_order_acquire), 1U);
        EXPECT_EQ(Task->Result().Outcome, Prism::Lifecycle::TaskOutcome::Quarantined);
    }

TEST(TaskLifecycle, ReclaimerFailureBlocksDrainInsteadOfHanging)
    {
        Net::io_context Ioc;
        Prism::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Started = std::make_shared<std::atomic<bool>>(false);
        auto Completed = std::make_shared<std::atomic<bool>>(false);
        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            WaitForSignalAndMark(Release, Started, Completed));
        ASSERT_TRUE(Task);

        IoThreadGroup IoThreads(Ioc);
        IoThreads.Start(1U);
        while (!Started->load(std::memory_order_acquire))
        {
            Started->wait(false, std::memory_order_acquire);
        }
        Registry.Reclaimer()->Quarantine();
        (void)Registry.Cancel();

        std::promise<void> Drained;
        auto DrainedFuture = Drained.get_future();
        Net::co_spawn(
            Ioc,
            Registry.Drain(),
            [&Drained](std::exception_ptr Failure,
                       std::expected<void, Prism::Fault::Failure> Result)
            {
                EXPECT_FALSE(Failure);
                EXPECT_FALSE(Result);
                Drained.set_value();
            });
        const auto Status = DrainedFuture.wait_for(std::chrono::milliseconds(100));
        Ioc.stop();
        IoThreads.Join();

        EXPECT_EQ(Status, std::future_status::ready);
        EXPECT_TRUE(Registry.IsDrainBlocked());
        EXPECT_FALSE(Completed->load(std::memory_order_acquire));
    }

TEST(TaskLifecycle, UnavailableRetirementRemainsStoredUntilExecutorRecovers)
{
    auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
    auto Context = Prism::Executor::ContextOwner::Create(Storage);
    {
        Prism::Lifecycle::TaskRegistry Registry(Context->Io.get_executor());
        Context->Io.stop();
    }

    EXPECT_EQ(Storage->Pending(), 1U);
    Storage->Collect();
    EXPECT_EQ(Storage->Pending(), 1U);

    Context->Io.restart();
    Storage->Retry();
    Context->Io.run();
    EXPECT_EQ(Storage->Pending(), 0U);
}

TEST(TaskLifecycle, QuarantinedParentCancellationBlocksChildTaskAdmission)
    {
        Net::io_context Ioc;
        Prism::Lifecycle::TaskRegistry Parent(Ioc.get_executor());
        const auto Child = Parent.CreateChild();
        ASSERT_NE(Child, nullptr);

        auto Started = std::make_shared<std::atomic<bool>>(false);
        const auto Task = Child->SpawnTracked(
            Request(Identity(Prism::TaskId{})), SetFlag(Started));
        ASSERT_TRUE(Task);

        Parent.Reclaimer()->Quarantine();
        EXPECT_TRUE(Parent.Cancel());
        EXPECT_TRUE(Parent.IsDrainBlocked());
        EXPECT_TRUE(Parent.Domain()->IsCancellationRequested());
        EXPECT_FALSE(Parent.Domain()->IsCancelled());
        EXPECT_TRUE(Parent.Domain()->IsDispatchBlocked());
        EXPECT_TRUE(Child->Domain()->IsCancellationRequested());
        EXPECT_FALSE(Child->Domain()->IsCancelled());
        EXPECT_TRUE(Child->Domain()->IsDispatchBlocked());

        const auto LateChild = Parent.CreateChild();
        ASSERT_NE(LateChild, nullptr);
        EXPECT_TRUE(LateChild->Domain()->IsCancellationRequested());
        EXPECT_FALSE(LateChild->Domain()->IsCancelled());
        EXPECT_TRUE(LateChild->Domain()->IsDispatchBlocked());
        EXPECT_FALSE(
            LateChild->SpawnTracked(
                Request(Identity(Prism::TaskId{})),
                []() -> Net::awaitable<void> { co_return; }()));

        const auto DrainResult = RunDrain(Ioc, Child->Drain());
        ASSERT_FALSE(DrainResult);
        EXPECT_EQ(DrainResult.error().Code, Prism::Fault::Code::Blocked);
        EXPECT_FALSE(Started->load(std::memory_order_acquire));
        EXPECT_FALSE(Task->IsCompleted());
        EXPECT_EQ(Task->Result().Outcome, Prism::Lifecycle::TaskOutcome::Pending);
        EXPECT_TRUE(Prism::Lifecycle::TaskHandleTestAccess::State(*Task)->Domain()->IsCancellationRequested());
        EXPECT_FALSE(Prism::Lifecycle::TaskHandleTestAccess::State(*Task)->Domain()->IsCancelled());
        EXPECT_TRUE(Prism::Lifecycle::TaskHandleTestAccess::State(*Task)->Domain()->IsDispatchBlocked());
        EXPECT_EQ(Task->CompletionCount(), 0U);
    }

TEST(TaskLifecycle, ParentStatsAggregateChildScopesWithoutDoubleCounting)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        Prism::Lifecycle::TaskRegistry Parent(Ioc.get_executor());
        auto First = Parent.CreateChild();
        auto Second = Parent.CreateChild();
        auto Failed = Parent.CreateChild();
        ASSERT_NE(First, nullptr);
        ASSERT_NE(Second, nullptr);
        ASSERT_NE(Failed, nullptr);

        auto FirstRelease = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto SecondRelease = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto FirstStarted = std::make_shared<std::atomic<bool>>(false);
        auto SecondStarted = std::make_shared<std::atomic<bool>>(false);
        auto FirstCompleted = std::make_shared<std::atomic<bool>>(false);
        auto SecondCompleted = std::make_shared<std::atomic<bool>>(false);

        auto FirstTask = First->SpawnTracked(
            Request(Identity(Prism::TaskId{}),
                    [FirstRelease]
                    { (void)FirstRelease->try_send(boost::system::error_code{}); }),
            WaitForSignalAndMark(FirstRelease, FirstStarted, FirstCompleted));
        auto SecondTask = Second->SpawnTracked(
            Request(Identity(Prism::TaskId{}),
                    [SecondRelease]
                    { (void)SecondRelease->try_send(boost::system::error_code{}); }),
            WaitForSignalAndMark(SecondRelease, SecondStarted, SecondCompleted));
        ASSERT_TRUE(FirstTask);
        ASSERT_TRUE(SecondTask);

        IoThreadGroup IoThreads(Ioc);
        IoThreads.Start(1U);
        while (!FirstStarted->load(std::memory_order_acquire) ||
               !SecondStarted->load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }

        auto FirstDrain = std::promise<void>();
        auto FirstDrainFuture = FirstDrain.get_future();
        Net::co_spawn(Ioc, First->Drain(), std::bind_front(CompleteFirstDrain, &FirstDrain));
        EXPECT_TRUE(First->Cancel());
        FirstDrainFuture.wait();

        auto Stats = Parent.Stats();
        EXPECT_EQ(Stats.Active, 1U);
        EXPECT_EQ(Stats.Started, 2U);
        EXPECT_EQ(Stats.Completed, 1U);
        EXPECT_EQ(Stats.Cancelled, 1U);
        EXPECT_EQ(Stats.Failed, 0U);
        EXPECT_TRUE(FirstCompleted->load(std::memory_order_acquire));
        EXPECT_FALSE(SecondCompleted->load(std::memory_order_acquire));

        auto FailedTask = Failed->SpawnTracked(
            Request(Identity(Prism::TaskId{})),
            []() -> Net::awaitable<void>
            {
                throw std::runtime_error("child failure");
                co_return;
            }());
        ASSERT_TRUE(FailedTask);
        auto FailedDrain = std::promise<void>();
        auto FailedDrainFuture = FailedDrain.get_future();
        Net::co_spawn(Ioc, Failed->Drain(), std::bind_front(CompleteFailedDrain, &FailedDrain));
        FailedDrainFuture.wait();

        Stats = Parent.Stats();
        EXPECT_EQ(Stats.Active, 1U);
        EXPECT_EQ(Stats.Started, 3U);
        EXPECT_EQ(Stats.Completed, 2U);
        EXPECT_EQ(Stats.Cancelled, 1U);
        EXPECT_EQ(Stats.Failed, 1U);
        EXPECT_EQ(FailedTask->Result().Outcome, Prism::Lifecycle::TaskOutcome::Failed);

        auto SecondDrain = std::promise<void>();
        auto SecondDrainFuture = SecondDrain.get_future();
        Net::co_spawn(Ioc, Second->Drain(), std::bind_front(CompleteSecondDrain, &SecondDrain));
        EXPECT_TRUE(Second->Cancel());
        SecondDrainFuture.wait();

        Stats = Parent.Stats();
        EXPECT_EQ(Stats.Active, 0U);
        EXPECT_EQ(Stats.Started, 3U);
        EXPECT_EQ(Stats.Completed, 3U);
        EXPECT_EQ(Stats.Cancelled, 2U);
        EXPECT_EQ(Stats.Failed, 1U);
        EXPECT_TRUE(SecondCompleted->load(std::memory_order_acquire));

        First.reset();
        Second.reset();
        Failed.reset();
        Stats = Parent.Stats();
        EXPECT_EQ(Stats.Active, 0U);
        EXPECT_EQ(Stats.Started, 3U);
        EXPECT_EQ(Stats.Completed, 3U);
        EXPECT_EQ(Stats.Cancelled, 2U);
        EXPECT_EQ(Stats.Failed, 1U);

        Work.reset();
        Ioc.stop();
        IoThreads.Join();
    }

TEST(TaskLifecycle, ParentStatsRetainNestedChildHistoryAfterRegistryRetire)
    {
        Net::io_context Ioc;
        Prism::Lifecycle::TaskRegistry Parent(Ioc.get_executor());
        auto Child = Parent.CreateChild();
        ASSERT_NE(Child, nullptr);
        auto Grandchild = Child->CreateChild();
        ASSERT_NE(Grandchild, nullptr);

        const auto Task = Grandchild->SpawnTracked(
            Request(Identity(Prism::TaskId{})),
            []() -> Net::awaitable<void> { co_return; }());
        ASSERT_TRUE(Task);
        EXPECT_TRUE(RunDrain(Ioc, Grandchild->Drain()));
        EXPECT_EQ(Task->CompletionCount(), 1U);

        auto Stats = Parent.Stats();
        EXPECT_EQ(Stats.Active, 0U);
        EXPECT_EQ(Stats.Started, 1U);
        EXPECT_EQ(Stats.Completed, 1U);
        EXPECT_EQ(Stats.Cancelled, 0U);
        EXPECT_EQ(Stats.Failed, 0U);

        Grandchild.reset();
        Child.reset();
        Stats = Parent.Stats();
        EXPECT_EQ(Stats.Active, 0U);
        EXPECT_EQ(Stats.Started, 1U);
        EXPECT_EQ(Stats.Completed, 1U);
        EXPECT_EQ(Stats.Cancelled, 0U);
        EXPECT_EQ(Stats.Failed, 0U);
    }

TEST(TaskLifecycle, ParentStatsFollowGrandchildAfterMiddleRegistryRetires)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        Prism::Lifecycle::TaskRegistry Root(Ioc.get_executor());
        auto Child = Root.CreateChild();
        ASSERT_NE(Child, nullptr);
        auto Grandchild = Child->CreateChild();
        ASSERT_NE(Grandchild, nullptr);

        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Started = std::make_shared<std::atomic<bool>>(false);
        auto Completed = std::make_shared<std::atomic<bool>>(false);
        const auto Task = Grandchild->SpawnTracked(
            Request(Identity(Prism::TaskId{})),
            WaitForSignalAndMark(Release, Started, Completed));
        ASSERT_TRUE(Task);

        auto DrainReady = std::promise<void>();
        auto DrainFuture = DrainReady.get_future();
        IoThreadGroup IoThreads(Ioc);
        IoThreads.Start(1U);
        while (!Started->load(std::memory_order_acquire))
        {
            Started->wait(false, std::memory_order_acquire);
        }

        Child.reset();
        auto BeforeCompletion = Root.Stats();
        EXPECT_EQ(BeforeCompletion.Active, 1U);
        EXPECT_EQ(BeforeCompletion.Started, 1U);
        EXPECT_EQ(BeforeCompletion.Completed, 0U);

        Net::co_spawn(Ioc, Grandchild->Drain(),
                      [&DrainReady](std::exception_ptr Failure,
                                    std::expected<void, Prism::Fault::Failure> Result)
                      {
                          EXPECT_FALSE(Failure);
                          EXPECT_TRUE(Result);
                          DrainReady.set_value();
                      });
        ASSERT_TRUE(Release->try_send(boost::system::error_code{}));
        DrainFuture.wait();

        EXPECT_TRUE(Completed->load(std::memory_order_acquire));
        EXPECT_EQ(Task->Result().Outcome, Prism::Lifecycle::TaskOutcome::Succeeded);
        auto Stats = Root.Stats();
        EXPECT_EQ(Stats.Active, 0U);
        EXPECT_EQ(Stats.Started, 1U);
        EXPECT_EQ(Stats.Completed, 1U);
        EXPECT_EQ(Stats.Cancelled, 0U);
        EXPECT_EQ(Stats.Failed, 0U);

        Grandchild.reset();
        Stats = Root.Stats();
        EXPECT_EQ(Stats.Active, 0U);
        EXPECT_EQ(Stats.Started, 1U);
        EXPECT_EQ(Stats.Completed, 1U);

        Work.reset();
        Ioc.stop();
        IoThreads.Join();
    }

TEST(TaskLifecycle, AutomaticTaskIdsAreUniqueAcrossRegistries)
    {
        Net::io_context Ioc;
        Prism::Lifecycle::TaskRegistry FirstRegistry(Ioc.get_executor());
        Prism::Lifecycle::TaskRegistry SecondRegistry(Ioc.get_executor());
        const auto FirstTask = FirstRegistry.SpawnTracked(
            Request(Identity(Prism::TaskId{})),
            []() -> Net::awaitable<void> { co_return; }());
        const auto SecondTask = SecondRegistry.SpawnTracked(
            Request(Identity(Prism::TaskId{})),
            []() -> Net::awaitable<void> { co_return; }());

        ASSERT_TRUE(FirstTask);
        ASSERT_TRUE(SecondTask);
        ASSERT_TRUE(static_cast<bool>(FirstTask->Identity().TaskId));
        ASSERT_TRUE(static_cast<bool>(SecondTask->Identity().TaskId));
        EXPECT_NE(FirstTask->Identity().TaskId, SecondTask->Identity().TaskId);

        EXPECT_TRUE(RunDrain(Ioc, FirstRegistry.Drain()));
        EXPECT_TRUE(RunDrain(Ioc, SecondRegistry.Drain()));
    }

/**
 * @brief 保留原注册名称，验证 owner 自动分配不受外部 TaskId context 污染。
 * @details 外部指定 TaskId 入口已退役；固定 context 数值只保留原输入边界，
 *          断言覆盖 owner ID 的唯一性、单调性和 drain 完成。
 */
TEST(TaskLifecycle, ExplicitAndAutomaticTaskIdsNeverCollide)
    {
        Net::io_context Ioc;
        Prism::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        const auto First = Registry.SpawnTracked(
            Request(Identity(Prism::TaskId{0x1000000000000000ULL})),
            []() -> Net::awaitable<void> { co_return; }());
        const auto Second = Registry.SpawnTracked(
            Request(Identity(Prism::TaskId{})),
            []() -> Net::awaitable<void> { co_return; }());

        ASSERT_TRUE(First);
        ASSERT_TRUE(Second);
        EXPECT_NE(First->Identity().TaskId, Second->Identity().TaskId);
        EXPECT_GT(Second->Identity().TaskId.Value(), First->Identity().TaskId.Value());

        EXPECT_TRUE(RunDrain(Ioc, Registry.Drain()));
    }

/**
 * @brief 保留原注册名称，验证不同 registry 的 owner ID 不发生碰撞。
 * @details 外部指定 TaskId 入口已退役；重复 context 输入只用于证明各 registry
 *          使用同一正式 owner 分配事实，且 drain 后完成资源回收。
 */
TEST(TaskLifecycle, ExplicitTaskIdsAreUniqueAcrossRegistries)
    {
        Net::io_context Ioc;
        Prism::Lifecycle::TaskRegistry FirstRegistry(Ioc.get_executor());
        Prism::Lifecycle::TaskRegistry SecondRegistry(Ioc.get_executor());

        const auto FirstTask = FirstRegistry.SpawnTracked(
            Request(Identity(Prism::TaskId{0x4000000000000000ULL})),
            []() -> Net::awaitable<void> { co_return; }());
        const auto SecondTask = SecondRegistry.SpawnTracked(
            Request(Identity(Prism::TaskId{0x4000000000000000ULL})),
            []() -> Net::awaitable<void> { co_return; }());

        ASSERT_TRUE(FirstTask);
        ASSERT_TRUE(SecondTask);
        EXPECT_NE(FirstTask->Identity().TaskId, SecondTask->Identity().TaskId);

        EXPECT_TRUE(RunDrain(Ioc, FirstRegistry.Drain()));
        EXPECT_TRUE(RunDrain(Ioc, SecondRegistry.Drain()));
    }

