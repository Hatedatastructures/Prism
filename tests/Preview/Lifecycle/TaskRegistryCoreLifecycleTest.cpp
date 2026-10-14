/**
 * @file TaskRegistryCoreLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TaskLifecycleTestSupport.hpp"

namespace
{
    /**
     * @brief 执行被取消前置任务的操作体。
     * @param Executed 测试结果槽，保持到 Ioc.run() 完成。
     * @return 标记执行状态的异步操作。
     */
    auto RunCancelledOperation(bool &Executed) -> Net::awaitable<void>
    {
        Executed = true;
        co_return;
    }

    /**
     * @brief 执行一段固定 TaskId 输入的并发生产范围。
     * @param Input 生产者所属 registry、计数槽、结果槽和半开范围。
     */
    struct TaskProductionRange final
    {
        Preview::Lifecycle::TaskRegistry *Registry{};
        std::atomic<std::size_t> *Produced{};
        std::vector<Preview::Lifecycle::TaskHandle> *Tasks{};
        std::uint64_t First{};
        std::uint64_t Last{};
    };

    auto ProduceTasks(TaskProductionRange Input) -> void
    {
        for (std::uint64_t Value = Input.First; Value < Input.Last; ++Value)
        {
            auto Task = Input.Registry->SpawnTracked(
                Request(Identity(Preview::TaskId{Value})),
                []() -> Net::awaitable<void> { co_return; }());
            if (Task)
            {
                Input.Produced->fetch_add(1, std::memory_order_relaxed);
                Input.Tasks->push_back(std::move(*Task));
            }
        }
    }
} // namespace

TEST(TaskLifecycle, CancelBeforeStartSkipsOperationAndCompletesOnce)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        bool Executed = false;

        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            RunCancelledOperation(Executed));
        ASSERT_TRUE(Task);

        (void)Registry.Cancel();
        const auto Failure = RunDrain(Ioc, Registry.Drain());

        ASSERT_TRUE(Failure);
        EXPECT_FALSE(Executed);
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->Result().Outcome, Preview::Lifecycle::TaskOutcome::Cancelled);
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
        EXPECT_EQ(Registry.Stats().Completed, 1U);
        EXPECT_EQ(Registry.Stats().Cancelled, 1U);
    }

TEST(TaskLifecycle, ParentCancellationPropagatesToChildDomain)
    {
        Net::io_context Ioc;
        auto Parent = std::make_shared<Preview::Lifecycle::CancellationDomain>(Ioc.get_executor());
        auto Child = Parent->CreateChild();

        ASSERT_NE(Child, nullptr);
        EXPECT_FALSE(Child->IsCancelled());
        EXPECT_TRUE(Parent->Cancel());
        Ioc.run();
        EXPECT_TRUE(Parent->IsCancelled());
        EXPECT_TRUE(Child->IsCancelled());
        EXPECT_FALSE(Parent->Cancel());
        EXPECT_FALSE(Child->Cancel());
    }

TEST(TaskLifecycle, ChildRetainsCancellationRequestAfterParentScopeEnds)
    {
        Net::io_context Ioc;
        std::shared_ptr<Preview::Lifecycle::CancellationDomain> Child;
        {
            auto Parent = std::make_shared<Preview::Lifecycle::CancellationDomain>(Ioc.get_executor());
            Parent->RequestCancellation();
            Child = Parent->CreateChild();
            ASSERT_NE(Child, nullptr);
            Ioc.run();
        }

        EXPECT_TRUE(Child->IsCancellationRequested());
        EXPECT_FALSE(Child->IsCancelled());
    }

TEST(TaskLifecycle, ParentCancellationRequestPreventsTaskStateStart)
    {
        Net::io_context Ioc;
        auto Parent = std::make_shared<Preview::Lifecycle::CancellationDomain>(Ioc.get_executor());
        auto RegistryDomain = Parent->CreateChild();
        auto TaskDomain = RegistryDomain->CreateChild();
        auto Task = std::make_shared<Preview::Lifecycle::TaskState>(
            Preview::Lifecycle::TaskState::Options{Identity(), TaskDomain, {}, false, {}});

        Parent->RequestCancellation();
        const auto Started = Task->TryStart();
        if (Started)
        {
            (void)Task->Complete();
        }
        Ioc.run();

        EXPECT_TRUE(TaskDomain->IsCancellationRequested());
        EXPECT_FALSE(Started);
        EXPECT_TRUE(Task->IsCancelRequested());
    }

TEST(TaskLifecycle, CancellationStatePrecedesDomainSignalOnMultiThreadExecutor)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Started = std::make_shared<std::atomic<bool>>(false);
        auto Completed = std::make_shared<std::atomic<bool>>(false);
        auto CancelStateAtHook = std::make_shared<std::promise<bool>>();
        auto CancelStateFuture = CancelStateAtHook->get_future();
        auto TaskState = std::make_shared<std::weak_ptr<Preview::Lifecycle::TaskState>>();
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Task = Registry.SpawnTracked(
            Request(
                Identity(),
                [TaskState, CancelStateAtHook]
                {
                    const auto Value = TaskState->lock();
                    CancelStateAtHook->set_value(Value && Value->IsCancelRequested());
                }),
            WaitForSignalAndMark(Release, Started, Completed));
        ASSERT_TRUE(Task);
        *TaskState = Preview::Lifecycle::TaskHandleTestAccess::State(*Task);

        std::thread IoThread([&Ioc] { Ioc.run(); });
        while (!Started->load(std::memory_order_acquire))
        {
            Started->wait(false, std::memory_order_acquire);
        }

        EXPECT_TRUE(Registry.Cancel());
        const auto CancelStatus = CancelStateFuture.wait_for(std::chrono::seconds(1));
        std::optional<bool> CancelledBeforeSignal;
        if (CancelStatus == std::future_status::ready)
        {
            CancelledBeforeSignal = CancelStateFuture.get();
        }

        (void)Release->try_send(boost::system::error_code{});
        auto DrainReady = std::make_shared<std::promise<std::exception_ptr>>();
        auto DrainFuture = DrainReady->get_future();
        Net::co_spawn(
            Ioc, Registry.Drain(),
            [DrainReady](std::exception_ptr Failure,
                         std::expected<void, Preview::Fault::Failure> Result)
            {
                DrainReady->set_value(Failure || !Result
                                          ? std::make_exception_ptr(std::runtime_error("drain blocked"))
                                          : std::exception_ptr{});
            });
        const auto DrainStatus = DrainFuture.wait_for(std::chrono::seconds(1));
        if (DrainStatus != std::future_status::ready)
        {
            Ioc.stop();
        }
        Work.reset();
        IoThread.join();

        EXPECT_EQ(CancelStatus, std::future_status::ready);
        ASSERT_TRUE(CancelledBeforeSignal.has_value());
        EXPECT_TRUE(*CancelledBeforeSignal);
        ASSERT_EQ(DrainStatus, std::future_status::ready);
        EXPECT_EQ(DrainFuture.get(), nullptr);
        EXPECT_TRUE(Completed->load(std::memory_order_acquire));
        EXPECT_TRUE(Task->IsCompleted());
    }

TEST(TaskLifecycle, CancelAndCompleteRaceCountsOneCompletion)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        std::size_t CancelCalls = 0;

        auto Task = Registry.SpawnTracked(
            Request(Identity(), [&CancelCalls] { ++CancelCalls; }),
            WaitForSignal(Release));
        ASSERT_TRUE(Task);

        Net::post(Ioc, [&Registry] { (void)Registry.Cancel(); });
        Net::post(Ioc, [Release] { Release->try_send(boost::system::error_code{}); });

        const auto Failure = RunDrain(Ioc, Registry.Drain());

        ASSERT_TRUE(Failure);
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
        EXPECT_EQ(Registry.Stats().Completed, 1U);
        EXPECT_TRUE(Task->Result().Outcome == Preview::Lifecycle::TaskOutcome::Cancelled ||
                    Task->Result().Outcome == Preview::Lifecycle::TaskOutcome::Succeeded);
        EXPECT_EQ(CancelCalls,
                  Task->Result().Outcome == Preview::Lifecycle::TaskOutcome::Cancelled ? 1U : 0U);
        EXPECT_EQ(Registry.Stats().Cancelled + Registry.Stats().Failed +
                      (Registry.Stats().Completed - Registry.Stats().Cancelled -
                       Registry.Stats().Failed),
                  1U);
    }

TEST(TaskLifecycle, ExceptionCompletionReportsTheOriginalFailureOnce)
    {
        Net::io_context Ioc;
        std::size_t FailureCalls = 0;
        Preview::Fault::Code ObservedFailure = Preview::Fault::Code::Success;
        Preview::Lifecycle::TaskRegistry Registry(
            Ioc.get_executor(),
            [&FailureCalls, &ObservedFailure](
                const Preview::Lifecycle::TaskIdentity &, Preview::Fault::Failure Failure)
            {
                ++FailureCalls;
                ObservedFailure = Failure.Code;
            });

        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            []() -> Net::awaitable<void>
            {
                throw std::runtime_error("lifecycle failure");
                co_return;
            }());
        ASSERT_TRUE(Task);

        const auto Failure = RunDrain(Ioc, Registry.Drain());

        ASSERT_TRUE(Failure);
        EXPECT_EQ(FailureCalls, 1U);
        EXPECT_EQ(ObservedFailure, Preview::Fault::Code::IoError);
        EXPECT_EQ(Task->Result().Outcome, Preview::Lifecycle::TaskOutcome::Failed);
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(Registry.Stats().Failed, 1U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
    }

TEST(TaskLifecycle, CompletionBeforeQueuedStartStillReportsFailureExactlyOnce)
    {
        Net::io_context Ioc;
        std::size_t FailureCalls = 0;
        Preview::Fault::Code ObservedFailure = Preview::Fault::Code::Success;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor(),
            [&FailureCalls, &ObservedFailure](
                const Preview::Lifecycle::TaskIdentity &, Preview::Fault::Failure Failure)
            {
                ++FailureCalls;
                ObservedFailure = Failure.Code;
            });
        bool Executed = false;
        auto Operation = [&Executed]() -> Net::awaitable<void>
        { Executed = true; co_return; };
        auto Task = Registry.SpawnTracked(Request(Identity()), Operation());
        ASSERT_TRUE(Task);
        const Preview::Fault::Failure Original{Preview::Fault::Code::IoError};
        ASSERT_TRUE(Preview::Lifecycle::TaskHandleTestAccess::State(*Task)->Complete(Original));
        EXPECT_FALSE(Preview::Lifecycle::TaskHandleTestAccess::State(*Task)->Complete(Original));
        const auto DrainFailure = RunDrain(Ioc, Registry.Drain());
        EXPECT_TRUE(DrainFailure);
        EXPECT_FALSE(Executed);
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(Registry.Stats().Started, 0U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
        EXPECT_EQ(Registry.Stats().Completed, 1U);
        EXPECT_EQ(Registry.Stats().Failed, 1U);
        EXPECT_EQ(FailureCalls, 1U);
        EXPECT_EQ(ObservedFailure, Preview::Fault::Code::IoError);
    }

TEST(TaskLifecycle, DrainWaitsForTheActualActiveCounterToReachZero)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto DrainFinished = std::make_shared<bool>(false);
        bool ObservedPending = false;

        auto Task = Registry.SpawnTracked(Request(Identity()), WaitForSignal(Release));
        ASSERT_TRUE(Task);
        (void)Registry.Cancel();

        Net::co_spawn(
            Ioc,
            Registry.Drain(),
            [DrainFinished](std::exception_ptr Failure,
                            std::expected<void, Preview::Fault::Failure> Result)
            {
                EXPECT_FALSE(Failure);
                EXPECT_TRUE(Result);
                *DrainFinished = true;
            });
        Net::post(
            Ioc,
            [&ObservedPending, Release]
            {
                ObservedPending = true;
                Release->try_send(boost::system::error_code{});
            });

        const auto Failure = RunCoro(Ioc, []() -> Net::awaitable<void> { co_return; }());

        ASSERT_EQ(Failure, nullptr);
        EXPECT_TRUE(ObservedPending);
        EXPECT_TRUE(*DrainFinished);
        EXPECT_EQ(Registry.Stats().Active, 0U);
    }

TEST(TaskLifecycle, RegistryTeardownQuarantinesLateCompletion)
    {
        Net::io_context Ioc;
        std::size_t FailureCalls = 0;
        std::optional<Preview::Lifecycle::TaskHandle> Task;

        {
            auto Registry = std::make_unique<Preview::Lifecycle::TaskRegistry>(
                Ioc.get_executor(),
                [&FailureCalls](const Preview::Lifecycle::TaskIdentity &, Preview::Fault::Failure)
                { ++FailureCalls; });
            auto Submitted = Registry->SpawnTracked(
                Request(Identity()),
                []() -> Net::awaitable<void>
                {
                    co_return;
                }());
            ASSERT_TRUE(Submitted);
            Task.emplace(std::move(*Submitted));
        }

        EXPECT_EQ(Task->Result().Outcome, Preview::Lifecycle::TaskOutcome::Pending);
        (void)Preview::Lifecycle::TaskHandleTestAccess::State(*Task)->Complete();
        Ioc.run();
        EXPECT_EQ(Task->Result().Outcome, Preview::Lifecycle::TaskOutcome::Succeeded);
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(FailureCalls, 0U);
    }

TEST(TaskLifecycle, ReclaimerRunsOnBoundExecutorAndQuarantinesQueuedWork)
    {
        Net::io_context Ioc;
        auto Reclaimer = std::make_shared<Preview::Executor::ExecutorReclaimer>(Ioc.get_executor());
        const auto Caller = std::this_thread::get_id();
        std::thread::id ExecutorThread;
        std::atomic<bool> Posted{false};
        std::atomic<bool> Accepted{false};

        std::thread Producer(
            [&Reclaimer, &ExecutorThread, &Posted, &Accepted]
            {
                Accepted.store(static_cast<bool>(Reclaimer->Post(
                    [&ExecutorThread, &Posted]
                    {
                        ExecutorThread = std::this_thread::get_id();
                        Posted.store(true, std::memory_order_release);
                    })),
                    std::memory_order_release);
            });
        Producer.join();
        ASSERT_TRUE(Accepted.load(std::memory_order_acquire));
        Ioc.run();

        EXPECT_TRUE(Posted.load(std::memory_order_acquire));
        EXPECT_EQ(ExecutorThread, Caller);

        Ioc.restart();
        Posted.store(false, std::memory_order_release);
        ASSERT_TRUE(Reclaimer->Post([&Posted] { Posted.store(true, std::memory_order_release); }));
        Reclaimer->Quarantine();
        Ioc.run();

        EXPECT_FALSE(Posted.load(std::memory_order_acquire));
        EXPECT_EQ(Reclaimer->QuarantinedCount(), 1U);
        EXPECT_EQ(Reclaimer->Pending(), 0U);
    }

TEST(TaskLifecycle, MultiThreadCancelAndCompletePublishesOneClassification)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Started = std::make_shared<std::atomic<bool>>(false);
        auto Completed = std::make_shared<std::atomic<bool>>(false);

        auto Task = Registry.SpawnTracked(
            Request(Identity(Preview::TaskId{})),
            WaitForSignalAndMark(Release, Started, Completed));
        ASSERT_TRUE(Task);

        std::vector<std::thread> IoThreads;
        for (std::size_t Index = 0; Index < 2; ++Index)
        {
            IoThreads.emplace_back([&Ioc] { Ioc.run(); });
        }
        while (!Started->load(std::memory_order_acquire))
        {
            Started->wait(false, std::memory_order_acquire);
        }

        std::barrier Gate(3);
        std::atomic<bool> CancelResult{false};
        std::atomic<bool> CompleteResult{false};
        std::thread Canceller(
            [&]
            {
                Gate.arrive_and_wait();
                CancelResult.store(Registry.Cancel(), std::memory_order_release);
            });
        std::thread Completer(
            [&]
            {
                Gate.arrive_and_wait();
                CompleteResult.store(
                    Preview::Lifecycle::TaskHandleTestAccess::State(*Task)->Complete(),
                    std::memory_order_release);
            });
        Gate.arrive_and_wait();
        Canceller.join();
        Completer.join();

        EXPECT_TRUE(CancelResult.load(std::memory_order_acquire));
        EXPECT_TRUE(CompleteResult.load(std::memory_order_acquire));
        EXPECT_TRUE(Release->try_send(boost::system::error_code{}));
        while (!Completed->load(std::memory_order_acquire))
        {
            Completed->wait(false, std::memory_order_acquire);
        }
        Work.reset();
        for (auto &IoThread : IoThreads)
        {
            IoThread.join();
        }

        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(Registry.Stats().Completed, 1U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
        EXPECT_EQ(
            Registry.Stats().Cancelled + Registry.Stats().Failed +
                (Registry.Stats().Completed - Registry.Stats().Cancelled - Registry.Stats().Failed),
            1U);
    }

TEST(TaskLifecycle, MultiThreadProducersUseOneRegistryCommandPath)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        std::atomic<std::size_t> Produced{0};
        std::vector<Preview::Lifecycle::TaskHandle> TasksA;
        std::vector<Preview::Lifecycle::TaskHandle> TasksB;
        std::vector<std::thread> IoThreads;
        for (std::size_t Index = 0; Index < 2; ++Index)
        {
            IoThreads.emplace_back([&Ioc] { Ioc.run(); });
        }

        std::thread ProducerA(
            ProduceTasks,
            TaskProductionRange{&Registry, &Produced, &TasksA, 101, 181});
        std::thread ProducerB(
            ProduceTasks,
            TaskProductionRange{&Registry, &Produced, &TasksB, 201, 281});
        ProducerA.join();
        ProducerB.join();
        (void)Registry.Cancel();
        Work.reset();
        for (auto &IoThread : IoThreads)
        {
            IoThread.join();
        }

        EXPECT_EQ(Produced.load(std::memory_order_acquire), 160U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
        EXPECT_EQ(Registry.Stats().Completed, 160U);
        TasksA.insert(
            TasksA.end(),
            std::make_move_iterator(TasksB.begin()),
            std::make_move_iterator(TasksB.end()));
        for (const auto &Task : TasksA)
        {
            EXPECT_EQ(Task.CompletionCount(), 1U);
        }
    }
