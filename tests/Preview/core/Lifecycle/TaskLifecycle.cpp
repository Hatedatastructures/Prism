/**
 * @file TaskLifecycle.cpp
 * @brief Preview 生命周期原语的确定性契约测试
 * @details 这些测试不依赖固定 grace 时间；所有收口都由明确的事件和计数推进。
 */

#include <gtest/gtest.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <barrier>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <Preview/Lifecycle/CancellationDomain.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Resource/ExecutorReclaimer.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/SessionControl.hpp>

namespace
{

    namespace Net = boost::asio;
    using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    auto WaitForSignal(std::shared_ptr<Signal> Ready) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await Ready->async_receive(Net::redirect_error(Net::use_awaitable, ErrorCode));
    }

    auto WaitForSignalAndMark(std::shared_ptr<Signal> Ready,
                              std::shared_ptr<std::atomic<bool>> Started,
                              std::shared_ptr<std::atomic<bool>> Completed) -> Net::awaitable<void>
    {
        Started->store(true, std::memory_order_release);
        Started->notify_all();
        co_await WaitForSignal(std::move(Ready));
        Completed->store(true, std::memory_order_release);
        Completed->notify_all();
    }

    auto SetFlag(std::shared_ptr<std::atomic<bool>> Flag) -> Net::awaitable<void>
    {
        Flag->store(true, std::memory_order_release);
        co_return;
    }

    auto RunCoro(Net::io_context &Ioc, Net::awaitable<void> Operation) -> std::exception_ptr
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Ioc,
            std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Ioc.run();
        return Failure;
    }

    auto Identity(Preview::TaskId TaskValue = Preview::TaskId{41}) -> Preview::Lifecycle::TaskIdentity
    {
        return Preview::Lifecycle::TaskIdentity{
            TaskValue,
            Preview::SessionId{7},
            Preview::StreamId{9},
            Preview::WorkerId{11},
            Preview::GenerationId{13}};
    }

    auto Request(Preview::Lifecycle::TaskIdentity IdentityValue,
                 Preview::Lifecycle::TaskState::CancelFn Cancel = {})
        -> Preview::Lifecycle::TaskRequest
    {
        return Preview::Lifecycle::TaskRequest{std::move(IdentityValue), std::move(Cancel)};
    }

    auto RunListenerIdentityScenario(Net::io_context &Ioc,
                                     Preview::Runtime::TcpListener &Listener,
                                     const std::shared_ptr<Preview::Runtime::SessionControl> &Control,
                                     const std::shared_ptr<Signal> &ErrorReady,
                                     Preview::Fault::Code &StartResult) -> Net::awaitable<void>
    {
        StartResult = co_await Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        if (StartResult != Preview::Fault::Code::Success)
        {
            co_return;
        }

        Net::ip::tcp::socket Client(Ioc);
        boost::system::error_code ErrorCode;
        co_await Client.async_connect(
            Net::ip::tcp::endpoint(
                Net::ip::address_v4::loopback(), Listener.LocalEndpoint().port()),
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode);
        if (ErrorCode)
        {
            Listener.Stop();
            co_return;
        }

        Client.close(ErrorCode);
        co_await ErrorReady->async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode);
        co_await Listener.Shutdown();
        co_await Control->Drain();
    }

    TEST(TaskLifecycle, CancelBeforeStartSkipsOperationAndCompletesOnce)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        bool Executed = false;

        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            [&Executed]() -> Net::awaitable<void>
            {
                Executed = true;
                co_return;
            }());
        ASSERT_NE(Task, nullptr);

        (void)Registry.Cancel();
        const auto Failure = RunCoro(Ioc, Registry.Drain());

        ASSERT_EQ(Failure, nullptr);
        EXPECT_FALSE(Executed);
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->Outcome(), Preview::Lifecycle::TaskOutcome::Cancelled);
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
            Preview::Lifecycle::TaskState::Options{
                Identity(), TaskDomain, Parent->Reclaimer(), {}, false},
            Preview::Lifecycle::TaskState::CompletionSink{});

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
        auto CancelStateAtSignal = std::make_shared<std::promise<bool>>();
        auto CancelStateFuture = CancelStateAtSignal->get_future();
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            WaitForSignalAndMark(Release, Started, Completed));
        ASSERT_NE(Task, nullptr);
        Task->CancellationSlot().assign(
            [Task, CancelStateAtSignal](Net::cancellation_type_t)
            { CancelStateAtSignal->set_value(Task->IsCancelRequested()); });

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
            [DrainReady](std::exception_ptr Failure)
            { DrainReady->set_value(std::move(Failure)); });
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
        ASSERT_NE(Task, nullptr);

        Net::post(Ioc, [&Registry] { (void)Registry.Cancel(); });
        Net::post(Ioc, [Release] { Release->try_send(boost::system::error_code{}); });

        const auto Failure = RunCoro(Ioc, Registry.Drain());

        ASSERT_EQ(Failure, nullptr);
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
        EXPECT_EQ(Registry.Stats().Completed, 1U);
        EXPECT_TRUE(Task->Outcome() == Preview::Lifecycle::TaskOutcome::Cancelled ||
                    Task->Outcome() == Preview::Lifecycle::TaskOutcome::Succeeded);
        EXPECT_EQ(CancelCalls,
                  Task->Outcome() == Preview::Lifecycle::TaskOutcome::Cancelled ? 1U : 0U);
        EXPECT_EQ(Registry.Stats().Cancelled + Registry.Stats().Failed +
                      (Registry.Stats().Completed - Registry.Stats().Cancelled -
                       Registry.Stats().Failed),
                  1U);
    }

    TEST(TaskLifecycle, ExceptionCompletionReportsTheOriginalFailureOnce)
    {
        Net::io_context Ioc;
        std::size_t FailureCalls = 0;
        std::string Message;
        Preview::Lifecycle::TaskRegistry Registry(
            Ioc.get_executor(),
            [&FailureCalls, &Message](const Preview::Lifecycle::TaskIdentity &, std::exception_ptr Failure)
            {
                ++FailureCalls;
                try
                {
                    if (Failure)
                    {
                        std::rethrow_exception(Failure);
                    }
                }
                catch (const std::exception &Error)
                {
                    Message = Error.what();
                }
            });

        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            []() -> Net::awaitable<void>
            {
                throw std::runtime_error("lifecycle failure");
                co_return;
            }());
        ASSERT_NE(Task, nullptr);

        const auto Failure = RunCoro(Ioc, Registry.Drain());

        ASSERT_EQ(Failure, nullptr);
        EXPECT_EQ(FailureCalls, 1U);
        EXPECT_EQ(Message, "lifecycle failure");
        EXPECT_EQ(Task->Outcome(), Preview::Lifecycle::TaskOutcome::Failed);
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(Registry.Stats().Failed, 1U);
        EXPECT_EQ(Registry.Stats().Active, 0U);
    }

    TEST(TaskLifecycle, DrainWaitsForTheActualActiveCounterToReachZero)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto DrainFinished = std::make_shared<bool>(false);
        bool ObservedPending = false;

        auto Task = Registry.SpawnTracked(Request(Identity()), WaitForSignal(Release));
        ASSERT_NE(Task, nullptr);
        (void)Registry.Cancel();

        Net::co_spawn(
            Ioc,
            Registry.Drain(),
            [DrainFinished](std::exception_ptr Failure)
            {
                EXPECT_EQ(Failure, nullptr);
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
        std::shared_ptr<Preview::Lifecycle::TaskState> Task;

        {
            auto Registry = std::make_unique<Preview::Lifecycle::TaskRegistry>(
                Ioc.get_executor(),
                [&FailureCalls](const Preview::Lifecycle::TaskIdentity &, std::exception_ptr)
                { ++FailureCalls; });
            Task = Registry->SpawnTracked(
                Request(Identity()),
                []() -> Net::awaitable<void>
                {
                    co_return;
                }());
            ASSERT_NE(Task, nullptr);
        }

        EXPECT_EQ(Task->Outcome(), Preview::Lifecycle::TaskOutcome::Pending);
        (void)Task->Complete();
        Ioc.run();
        EXPECT_EQ(Task->Outcome(), Preview::Lifecycle::TaskOutcome::Succeeded);
        EXPECT_EQ(Task->CompletionCount(), 1U);
        EXPECT_EQ(FailureCalls, 0U);
    }

    TEST(TaskLifecycle, ReclaimerRunsOnBoundExecutorAndQuarantinesQueuedWork)
    {
        Net::io_context Ioc;
        auto Reclaimer = std::make_shared<Preview::Resource::ExecutorReclaimer>(Ioc.get_executor());
        const auto Caller = std::this_thread::get_id();
        std::thread::id ExecutorThread;
        std::atomic<bool> Posted{false};
        std::atomic<bool> Accepted{false};

        std::thread Producer(
            [&Reclaimer, &ExecutorThread, &Posted, &Accepted]
            {
                Accepted.store(Reclaimer->Post(
                    [&ExecutorThread, &Posted]
                    {
                        ExecutorThread = std::this_thread::get_id();
                        Posted.store(true, std::memory_order_release);
                    }),
                    std::memory_order_release);
            });
        Producer.join();
        ASSERT_TRUE(Accepted.load(std::memory_order_acquire));
        Ioc.run();

        EXPECT_TRUE(Posted.load(std::memory_order_acquire));
        EXPECT_EQ(ExecutorThread, Caller);

        Posted.store(false, std::memory_order_release);
        ASSERT_TRUE(Reclaimer->Post([&Posted] { Posted.store(true, std::memory_order_release); }));
        Reclaimer->Quarantine();
        Ioc.restart();
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
        ASSERT_NE(Task, nullptr);

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
                CompleteResult.store(Task->Complete(), std::memory_order_release);
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
        std::vector<std::shared_ptr<Preview::Lifecycle::TaskState>> TasksA;
        std::vector<std::shared_ptr<Preview::Lifecycle::TaskState>> TasksB;
        std::vector<std::thread> IoThreads;
        for (std::size_t Index = 0; Index < 2; ++Index)
        {
            IoThreads.emplace_back([&Ioc] { Ioc.run(); });
        }

        std::thread ProducerA(
            [&]
            {
                for (std::uint64_t Value = 101; Value < 181; ++Value)
                {
                    auto Task = Registry.SpawnTracked(
                        Request(Identity(Preview::TaskId{Value})),
                        []() -> Net::awaitable<void> { co_return; }());
                    if (Task)
                    {
                        ++Produced;
                        TasksA.push_back(std::move(Task));
                    }
                }
            });
        std::thread ProducerB(
            [&]
            {
                for (std::uint64_t Value = 201; Value < 281; ++Value)
                {
                    auto Task = Registry.SpawnTracked(
                        Request(Identity(Preview::TaskId{Value})),
                        []() -> Net::awaitable<void> { co_return; }());
                    if (Task)
                    {
                        ++Produced;
                        TasksB.push_back(std::move(Task));
                    }
                }
            });
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
            EXPECT_EQ(Task->CompletionCount(), 1U);
        }
    }

    TEST(TaskLifecycle, DrainCompletesBeforeRegistryRelease)
    {
        Net::io_context Ioc;
        auto Registry = std::make_unique<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
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
        ASSERT_NE(Task, nullptr);

        const auto Failure = RunCoro(
            Ioc,
            [&Registry]() -> Net::awaitable<void>
            {
                (void)Registry->Cancel();
                co_await Registry->Drain();
            }());

        ASSERT_EQ(Failure, nullptr);
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
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Started = std::make_shared<std::atomic<bool>>(false);
        auto Completed = std::make_shared<std::atomic<bool>>(false);
        std::atomic<bool> DrainFailure{false};
        std::atomic<bool> DrainFinished{false};

        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            WaitForSignalAndMark(Release, Started, Completed));
        ASSERT_NE(Task, nullptr);

        std::vector<std::thread> IoThreads;
        for (std::size_t Index = 0; Index < 2; ++Index)
        {
            IoThreads.emplace_back([&Ioc] { Ioc.run(); });
        }
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
            [DrainReady, &DrainFailure, &DrainFinished](std::exception_ptr Failure)
            {
                DrainFailure.store(static_cast<bool>(Failure), std::memory_order_release);
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
        for (auto &IoThread : IoThreads)
        {
            IoThread.join();
        }
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
        std::shared_ptr<Preview::Lifecycle::TaskState> Task;
        std::vector<std::thread> IoThreads;
        auto CancelStatus = std::future_status::timeout;

        {
            auto Registry = std::make_unique<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
            Task = Registry->SpawnTracked(
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
            ASSERT_NE(Task, nullptr);

            for (std::size_t Index = 0; Index < 2; ++Index)
            {
                IoThreads.emplace_back([&Ioc] { Ioc.run(); });
            }
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
            for (auto &IoThread : IoThreads)
            {
                IoThread.join();
            }
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
        std::shared_ptr<Preview::Lifecycle::TaskState> Task;

        {
            auto Registry = std::make_unique<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
            Task = Registry->SpawnTracked(
                Request(
                    Identity(),
                    [&CancelCalls] { CancelCalls.fetch_add(1, std::memory_order_relaxed); }),
                []() -> Net::awaitable<void> { co_return; }());
            ASSERT_NE(Task, nullptr);
        }

        Ioc.run();
        EXPECT_EQ(CancelCalls.load(std::memory_order_acquire), 1U);
        EXPECT_EQ(Task->Outcome(), Preview::Lifecycle::TaskOutcome::Quarantined);
    }

    TEST(TaskLifecycle, ReclaimerFailureBlocksDrainInsteadOfHanging)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        auto Release = std::make_shared<Signal>(Ioc.get_executor(), 1);
        std::atomic<bool> Started{false};
        auto Task = Registry.SpawnTracked(
            Request(Identity()),
            [&Started, Release]() -> Net::awaitable<void>
            {
                Started.store(true, std::memory_order_release);
                Started.notify_all();
                co_await WaitForSignal(Release);
            }());
        ASSERT_NE(Task, nullptr);

        std::thread IoThread([&Ioc] { Ioc.run(); });
        while (!Started.load(std::memory_order_acquire))
        {
            Started.wait(false, std::memory_order_acquire);
        }
        Registry.Reclaimer()->Quarantine();
        (void)Registry.Cancel();

        std::promise<void> Drained;
        auto DrainedFuture = Drained.get_future();
        Net::co_spawn(
            Ioc,
            Registry.Drain(),
            [&Drained](std::exception_ptr Failure)
            {
                EXPECT_EQ(Failure, nullptr);
                Drained.set_value();
            });
        const auto Status = DrainedFuture.wait_for(std::chrono::milliseconds(100));
        Ioc.stop();
        IoThread.join();

        EXPECT_EQ(Status, std::future_status::ready);
        EXPECT_TRUE(Registry.IsDrainBlocked());
    }

    TEST(TaskLifecycle, QuarantinedParentCancellationBlocksChildTaskAdmission)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Parent(Ioc.get_executor());
        const auto Child = Parent.CreateChild();
        ASSERT_NE(Child, nullptr);

        auto Started = std::make_shared<std::atomic<bool>>(false);
        const auto Task = Child->SpawnTracked(
            Request(Identity(Preview::TaskId{})), SetFlag(Started));
        ASSERT_NE(Task, nullptr);

        Parent.Reclaimer()->Quarantine();
        EXPECT_TRUE(Parent.Cancel());
        EXPECT_TRUE(Parent.IsDrainBlocked());
        EXPECT_TRUE(Parent.Domain()->IsCancellationRequested());
        EXPECT_TRUE(Parent.Domain()->IsCancelled());
        EXPECT_TRUE(Parent.Domain()->IsDispatchBlocked());
        EXPECT_TRUE(Child->Domain()->IsCancelled());
        EXPECT_TRUE(Child->Domain()->IsDispatchBlocked());

        const auto LateChild = Parent.CreateChild();
        ASSERT_NE(LateChild, nullptr);
        EXPECT_TRUE(LateChild->Domain()->IsCancelled());
        EXPECT_TRUE(LateChild->Domain()->IsDispatchBlocked());
        EXPECT_EQ(
            LateChild->SpawnTracked(
                Request(Identity(Preview::TaskId{})),
                []() -> Net::awaitable<void> { co_return; }()),
            nullptr);

        const auto Failure = RunCoro(Ioc, Child->Drain());
        EXPECT_EQ(Failure, nullptr);
        EXPECT_FALSE(Started->load(std::memory_order_acquire));
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->Outcome(), Preview::Lifecycle::TaskOutcome::Cancelled);
        EXPECT_TRUE(Task->Domain()->IsCancelled());
        EXPECT_TRUE(Task->Domain()->IsDispatchBlocked());
        EXPECT_TRUE(Task->IsCancelDispatchFailed());
    }

    TEST(TaskLifecycle, AutomaticTaskIdsAreUniqueAcrossRegistries)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry FirstRegistry(Ioc.get_executor());
        Preview::Lifecycle::TaskRegistry SecondRegistry(Ioc.get_executor());
        const auto FirstTask = FirstRegistry.SpawnTracked(
            Request(Identity(Preview::TaskId{})),
            []() -> Net::awaitable<void> { co_return; }());
        const auto SecondTask = SecondRegistry.SpawnTracked(
            Request(Identity(Preview::TaskId{})),
            []() -> Net::awaitable<void> { co_return; }());

        ASSERT_NE(FirstTask, nullptr);
        ASSERT_NE(SecondTask, nullptr);
        ASSERT_TRUE(static_cast<bool>(FirstTask->Identity().TaskId));
        ASSERT_TRUE(static_cast<bool>(SecondTask->Identity().TaskId));
        EXPECT_NE(FirstTask->Identity().TaskId, SecondTask->Identity().TaskId);

        const auto Failure = RunCoro(
            Ioc,
            [&FirstRegistry, &SecondRegistry]() -> Net::awaitable<void>
            {
                co_await FirstRegistry.Drain();
                co_await SecondRegistry.Drain();
            }());
        EXPECT_EQ(Failure, nullptr);
    }

    TEST(TaskLifecycle, ExplicitAndAutomaticTaskIdsNeverCollide)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry Registry(Ioc.get_executor());
        constexpr auto ExplicitValue = std::uint64_t{0x1000000000000000ULL};
        const auto Explicit = Registry.SpawnTracked(
            Request(Identity(Preview::TaskId{ExplicitValue})),
            []() -> Net::awaitable<void> { co_return; }());
        const auto Automatic = Registry.SpawnTracked(
            Request(Identity(Preview::TaskId{})),
            []() -> Net::awaitable<void> { co_return; }());

        ASSERT_NE(Explicit, nullptr);
        ASSERT_NE(Automatic, nullptr);
        EXPECT_NE(Explicit->Identity().TaskId, Automatic->Identity().TaskId);
        EXPECT_EQ(Explicit->Identity().TaskId.Value(), ExplicitValue);
        EXPECT_GT(Automatic->Identity().TaskId.Value(), Explicit->Identity().TaskId.Value());

        const auto Duplicate = Registry.SpawnTracked(
            Request(Identity(Preview::TaskId{ExplicitValue})),
            []() -> Net::awaitable<void> { co_return; }());
        EXPECT_EQ(Duplicate, nullptr);

        const auto Failure = RunCoro(Ioc, Registry.Drain());
        EXPECT_EQ(Failure, nullptr);
    }

    TEST(TaskLifecycle, ExplicitTaskIdsAreUniqueAcrossRegistries)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry FirstRegistry(Ioc.get_executor());
        Preview::Lifecycle::TaskRegistry SecondRegistry(Ioc.get_executor());
        constexpr auto ExplicitValue = std::uint64_t{0x4000000000000000ULL};

        const auto FirstTask = FirstRegistry.SpawnTracked(
            Request(Identity(Preview::TaskId{ExplicitValue})),
            []() -> Net::awaitable<void> { co_return; }());
        const auto DuplicateTask = SecondRegistry.SpawnTracked(
            Request(Identity(Preview::TaskId{ExplicitValue})),
            []() -> Net::awaitable<void> { co_return; }());

        ASSERT_NE(FirstTask, nullptr);
        EXPECT_EQ(DuplicateTask, nullptr);

        const auto Failure = RunCoro(
            Ioc,
            [&FirstRegistry, &SecondRegistry]() -> Net::awaitable<void>
            {
                co_await FirstRegistry.Drain();
                co_await SecondRegistry.Drain();
            }());
        EXPECT_EQ(Failure, nullptr);
    }

    TEST(SessionControlLifecycle, TaskIdentityReachesErrorHook)
    {
        Net::io_context Ioc;
        Preview::Runtime::SessionControl Control(Ioc.get_executor());
        std::optional<Preview::Lifecycle::TaskIdentity> Observed;
        Control.SetErrorHook(
            Preview::Runtime::SessionControl::IdentityErrorHook{
                [&Observed](const Preview::Lifecycle::TaskIdentity &IdentityValue,
                            Preview::Fault::Code,
                            std::exception_ptr)
            { Observed = IdentityValue; }});

        const auto Expected = Identity(Preview::TaskId{});
        ASSERT_TRUE(Control.Start(
            Request(Expected),
            []() -> Net::awaitable<void>
            {
                throw std::runtime_error("identity propagation");
                co_return;
            }()));

        const auto Failure = RunCoro(Ioc, Control.Drain());

        ASSERT_EQ(Failure, nullptr);
        ASSERT_TRUE(Observed.has_value());
        EXPECT_EQ(Observed->SessionId, Expected.SessionId);
        EXPECT_EQ(Observed->StreamId, Expected.StreamId);
        EXPECT_EQ(Observed->WorkerId, Expected.WorkerId);
        EXPECT_EQ(Observed->Generation, Expected.Generation);
        EXPECT_TRUE(static_cast<bool>(Observed->TaskId));
    }

    TEST(SessionControlLifecycle, HooksCloseAndMetricsRunOnBoundExecutor)
    {
        Net::io_context Ioc;
        auto Work = Net::make_work_guard(Ioc);
        Preview::Runtime::SessionControl Control(Ioc.get_executor());
        std::atomic<std::size_t> CancelCalls{0};
        std::atomic<std::size_t> CloseCalls{0};
        std::atomic<std::size_t> MetricsCalls{0};
        std::atomic<std::size_t> CallbackEntries{0};
        std::atomic<std::size_t> InCallback{0};
        std::atomic<bool> ConcurrentCallbacks{false};
        std::atomic<bool> HoldCallbacks{true};
        const auto ObserveCallback =
            [&]
            {
                if (InCallback.fetch_add(1, std::memory_order_acq_rel) != 0)
                {
                    ConcurrentCallbacks.store(true, std::memory_order_release);
                }
                CallbackEntries.fetch_add(1, std::memory_order_release);
                while (HoldCallbacks.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                InCallback.fetch_sub(1, std::memory_order_acq_rel);
            };

        ASSERT_TRUE(Control.AddCancelHook(
            [&]
            {
                CancelCalls.fetch_add(1, std::memory_order_relaxed);
                ObserveCallback();
            }));
        Control.SetMetricsHook(
            [&](const Preview::Runtime::SessionMetrics &)
            {
                MetricsCalls.fetch_add(1, std::memory_order_relaxed);
                ObserveCallback();
            });

        std::vector<std::thread> IoThreads;
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            IoThreads.emplace_back([&Ioc] { Ioc.run(); });
        }

        std::thread CallerThread(
            [&]
            {
                Control.Cancel();
                const auto Accepted = Control.CloseOnce(
                    [&]
                    {
                        CloseCalls.fetch_add(1, std::memory_order_relaxed);
                        ObserveCallback();
                    });
                EXPECT_TRUE(Accepted);
            });
        CallerThread.join();
        while (CallbackEntries.load(std::memory_order_acquire) == 0)
        {
            std::this_thread::yield();
        }
        HoldCallbacks.store(false, std::memory_order_release);
        Work.reset();
        for (auto &IoThread : IoThreads)
        {
            IoThread.join();
        }

        EXPECT_EQ(CancelCalls.load(std::memory_order_acquire), 1U);
        EXPECT_EQ(CloseCalls.load(std::memory_order_acquire), 1U);
        EXPECT_GT(MetricsCalls.load(std::memory_order_acquire), 0U);
        EXPECT_FALSE(ConcurrentCallbacks.load(std::memory_order_acquire));
    }

    TEST(SessionControlLifecycle, CloseOnceReportsReclaimerDeliveryFailure)
    {
        Preview::Runtime::SessionControl Control;

        EXPECT_FALSE(Control.CloseOnce([] {}));
        EXPECT_TRUE(Control.IsDrainBlocked());
        EXPECT_TRUE(Control.IsCloseDispatchFailed());
        EXPECT_TRUE(Control.Metrics().CloseDispatchFailed);
    }

    TEST(TcpListenerLifecycle, ListenerTaskIdentityReachesSessionErrorHook)
    {
        Net::io_context Ioc;
        auto Observed =
            std::make_shared<std::optional<Preview::Lifecycle::TaskIdentity>>();
        auto FactoryWorker = std::make_shared<std::optional<std::size_t>>();
        auto ErrorReady = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Control = std::make_shared<Preview::Runtime::SessionControl>();
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Factory =
            [Control, FactoryWorker, Observed, ErrorReady](Preview::SharedTransmission,
                                                            std::size_t Worker)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                *FactoryWorker = Worker;
                Control->SetErrorHook(
                    Preview::Runtime::SessionControl::IdentityErrorHook{
                        [Observed, ErrorReady](const Preview::Lifecycle::TaskIdentity &IdentityValue,
                                               Preview::Fault::Code,
                                               std::exception_ptr)
                        {
                            *Observed = IdentityValue;
                            (void)ErrorReady->try_send(boost::system::error_code{});
                        }});
                Preview::Runtime::SessionOptions Options;
                Options.Control = Control;
                return std::make_shared<Preview::Runtime::Session>(std::move(Options));
            };
        ListenerOptions.WorkerCount = 4;
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        auto StartResult = Preview::Fault::Code::GenericError;
        RunCoro(
            Ioc,
            RunListenerIdentityScenario(Ioc, Listener, Control, ErrorReady, StartResult));

        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        ASSERT_TRUE(FactoryWorker->has_value());
        ASSERT_TRUE(Observed->has_value());
        EXPECT_TRUE(static_cast<bool>((*Observed)->TaskId));
        EXPECT_TRUE(static_cast<bool>((*Observed)->SessionId));
        EXPECT_TRUE(static_cast<bool>((*Observed)->WorkerId));
        EXPECT_EQ((*Observed)->WorkerId, Preview::WorkerId{**FactoryWorker});
    }

    TEST(SessionControlLifecycle, CancelSealsFutureOperations)
    {
        Net::io_context Ioc;
        Preview::Runtime::SessionControl Control(Ioc.get_executor());
        bool Executed = false;

        Control.Cancel();
        EXPECT_FALSE(Control.Start(
            [&Executed]() -> Net::awaitable<void>
            {
                Executed = true;
                co_return;
            }()));
        Ioc.run();
        EXPECT_FALSE(Executed);
    }

    TEST(SessionControlLifecycle, WorkerRegistryBindingUsesIndependentChildScope)
    {
        Net::io_context Ioc;
        auto WorkerRegistry = std::make_shared<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Preview::Runtime::SessionControl First(Ioc.get_executor());
        Preview::Runtime::SessionControl Second(Ioc.get_executor());

        ASSERT_TRUE(First.Bind(Ioc.get_executor(), WorkerRegistry));
        ASSERT_TRUE(Second.Bind(Ioc.get_executor(), WorkerRegistry));
        First.Cancel();

        auto Executed = std::make_shared<std::atomic<bool>>(false);
        ASSERT_TRUE(Second.Start(
            SetFlag(Executed)));
        ASSERT_EQ(RunCoro(Ioc, WorkerRegistry->Drain()), nullptr);

        EXPECT_TRUE(Executed->load(std::memory_order_acquire));
        EXPECT_FALSE(WorkerRegistry->IsDrainBlocked());
    }

} // namespace
