/**
 * @file OwnershipTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "LifecycleTestSupport.hpp"
#include <Prism/Runtime/Session.hpp>
#include <Test/Prism/Runtime/Session/AdmissionSupport.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>

namespace
{
    /** @brief 保存同一 listener 身份检查的控制器、错误通知和启动观察槽。 */
    struct ListenerIdentityProbe final
    {
        std::shared_ptr<Prism::Runtime::SessionControl> Control;
        std::shared_ptr<Signal> FactoryReady;
        std::shared_ptr<Signal> ErrorReady;
        Prism::Fault::Code &StartResult;
    };

    /** @brief 为同一 listener 的错误通知保存身份观察者和实际控制器。 */
    struct ListenerIdentityFactory final
    {
        std::shared_ptr<Prism::Runtime::SessionControl> Control;
        std::shared_ptr<std::optional<Prism::WorkerId>> FactoryWorker;
        std::shared_ptr<std::optional<Prism::Lifecycle::TaskIdentity>> Observed;
        std::shared_ptr<Signal> FactoryReady;
        std::shared_ptr<Signal> ErrorReady;

        auto operator()(Prism::Runtime::SessionAdmission Admission)
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            *FactoryWorker = Admission.Worker;
            Control->SetErrorHook(Prism::Runtime::SessionControl::IdentityErrorHook{
                [Observed = Observed, ErrorReady = ErrorReady](
                    const Prism::Lifecycle::TaskIdentity &IdentityValue,
                     Prism::Fault::Failure)
                {
                    *Observed = IdentityValue;
                    (void)ErrorReady->try_send(boost::system::error_code{});
                }});
            EXPECT_TRUE(FactoryReady->try_send(boost::system::error_code{}));
            Prism::Runtime::SessionOptions Options;
            Options.Control = Control;
            Options.Services->Bytes = Prism::Testing::Runtime::MakeListenerTestBytePool();
            return std::make_shared<Prism::Runtime::Session>(std::move(Options));
        }
    };

    struct ThrowingListenerFactory final
    {
        std::shared_ptr<Signal> FactoryReady;

        auto operator()(Prism::Runtime::SessionAdmission)
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            EXPECT_TRUE(FactoryReady->try_send(boost::system::error_code{}));
            throw std::runtime_error("listener session factory failure");
        }
    };

    auto WaitForListenerSignalOrTimeout(
        const std::shared_ptr<Signal> &SignalValue,
        Net::io_context &Ioc) -> Net::awaitable<bool>
    {
        Net::steady_timer Timer(Ioc);
        Timer.expires_after(std::chrono::seconds(2));
        using Net::experimental::awaitable_operators::operator||;
        boost::system::error_code ErrorCode;
        auto Race = co_await (SignalValue->async_receive(
                                  Net::redirect_error(Net::use_awaitable, ErrorCode)) ||
                              Timer.async_wait(Net::use_awaitable));
        co_return Race.index() == 0U && !ErrorCode;
    }

    struct ListenerFactoryExceptionScenarioRequest final
    {
        Net::io_context &Ioc;
        Prism::Runtime::TcpListener &Listener;
        std::shared_ptr<Signal> FactoryReady;
        std::shared_ptr<Signal> FailureReady;
    };

    auto RunListenerFactoryExceptionScenario(
        ListenerFactoryExceptionScenarioRequest Request) -> Net::awaitable<void>
    {
        const auto Started = co_await Request.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Started, Prism::Fault::Code::Success);
        if (Started != Prism::Fault::Code::Success) co_return;
        Net::ip::tcp::socket Client(co_await Net::this_coro::executor);
        boost::system::error_code ErrorCode;
        co_await Client.async_connect(
            Net::ip::tcp::endpoint(
                Net::ip::address_v4::loopback(), Request.Listener.LocalEndpoint().port()),
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode);
        if (ErrorCode)
        {
            (void)co_await Request.Listener.Shutdown();
            co_return;
        }

        const bool FactoryCalled =
            co_await WaitForListenerSignalOrTimeout(Request.FactoryReady, Request.Ioc);
        EXPECT_TRUE(FactoryCalled);
        if (!FactoryCalled)
        {
            Client.close(ErrorCode);
            (void)co_await Request.Listener.Shutdown();
            co_return;
        }
        const bool FailureDelivered =
            co_await WaitForListenerSignalOrTimeout(Request.FailureReady, Request.Ioc);
        EXPECT_TRUE(FailureDelivered);
        Client.close(ErrorCode);
        const auto Shutdown = co_await Request.Listener.Shutdown();
        EXPECT_TRUE(Shutdown);
    }

    /**
     * @brief 在当前 executor 验证 listener 的任务身份并等待 listener/control 关闭。
     * @details Listener 和启动观察槽由调用测试保持到 run 返回；通知与 Control
     *          在协程内拥有。错误连接也等待 Shutdown，不留下 accept loop。
     */
    auto RunListenerIdentityScenario(Prism::Runtime::TcpListener &Listener,
        ListenerIdentityProbe Probe) -> Net::awaitable<void>
    {
        Probe.StartResult = co_await Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Probe.StartResult, Prism::Fault::Code::Success);
        if (Probe.StartResult != Prism::Fault::Code::Success)
        {
            co_return;
        }
        Net::ip::tcp::socket Client(co_await Net::this_coro::executor);
        boost::system::error_code ErrorCode;
        co_await Client.async_connect(
            Net::ip::tcp::endpoint(
                Net::ip::address_v4::loopback(), Listener.LocalEndpoint().port()),
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode);
        if (ErrorCode)
        {
            co_await Listener.Shutdown();
            co_return;
        }
        co_await Probe.FactoryReady->async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode);
        if (ErrorCode)
        {
            co_await Listener.Shutdown();
            co_return;
        }
        Client.close(ErrorCode);
        co_await Probe.ErrorReady->async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode);
        co_await Listener.Shutdown();
        const auto DrainResult = co_await Probe.Control->Drain();
        EXPECT_TRUE(DrainResult);
    }

    /**
     * @brief 构造被 sealed control 拒绝的任务操作体。
     * @param Executed 测试结果槽，保持到 Ioc.run() 完成。
     * @return 标记执行状态的异步操作。
     */
    auto RunSealedOperation(bool &Executed) -> Net::awaitable<void>
    {
        Executed = true;
        co_return;
    }

    /**
     * @brief 记录 SessionControl callback 的串行执行合同。
     */
    struct CallbackObservation final
    {
        std::atomic<std::size_t> &Entries;
        std::atomic<std::size_t> &InCallback;
        std::atomic<bool> &Concurrent;
        std::atomic<bool> &Hold;

        auto Record() const -> void
        {
            if (InCallback.fetch_add(1, std::memory_order_acq_rel) != 0)
            {
                Concurrent.store(true, std::memory_order_release);
            }
            Entries.fetch_add(1, std::memory_order_release);
            while (Hold.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            InCallback.fetch_sub(1, std::memory_order_acq_rel);
        }
    };

    /**
     * @brief 在 caller thread 执行取消和一次性关闭，并等待 callback 观察完成。
     */
    auto RunCancelCloseCallbacks(
        Prism::Runtime::SessionControl &Control,
        std::atomic<std::size_t> &CloseCalls,
        const CallbackObservation &Observation) -> void
    {
        const auto Installed = Control.SetCloseAction(
            [&CloseCalls, &Observation]()
            -> std::expected<void, Prism::Fault::Failure>
            {
                CloseCalls.fetch_add(1, std::memory_order_relaxed);
                Observation.Record();
                return {};
            });
        EXPECT_TRUE(Installed);
        EXPECT_TRUE(Control.Cancel());
        const auto Accepted = Control.CloseOnce();
        EXPECT_TRUE(Accepted);
    }

    using TaskPageResult = std::expected<Prism::Lifecycle::TaskRegistryListPage,
                                         Prism::Fault::Failure>;

    /** @brief 枚举准确 session 的任务快照，再经真实 registry drain 释放测试 owner。 */
    auto RunTaskRegistryListScenario(
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Registry,
        std::shared_ptr<Signal> Ready) -> Net::awaitable<TaskPageResult>
    {
        auto Listed = co_await Registry->ListTasks(
            Prism::Lifecycle::TaskRegistryListRequest{
                Prism::SessionId{7}, Prism::WorkerId{11}, Prism::GenerationId{13}, 0U, 10U});
        (void)Ready->try_send(boost::system::error_code{});
        (void)Ready->try_send(boost::system::error_code{});
        (void)Ready->try_send(boost::system::error_code{});
        const auto Drained = co_await Registry->Drain();
        Registry.reset();
        if (!Drained)
        {
            co_return std::unexpected(Drained.error());
        }
        co_return std::move(Listed);
    }
} // namespace

TEST(SessionControlLifecycle, TaskIdentityReachesErrorHook)
    {
        Net::io_context Ioc;
        Prism::Runtime::SessionControl Control(Ioc.get_executor());
        std::optional<Prism::Lifecycle::TaskIdentity> Observed;
        Control.SetErrorHook(
            Prism::Runtime::SessionControl::IdentityErrorHook{
                [&Observed](const Prism::Lifecycle::TaskIdentity &IdentityValue,
                             Prism::Fault::Failure)
            { Observed = IdentityValue; }});

        const auto Expected = Identity(Prism::TaskId{});
        const auto Submitted = Control.Start(
            Request(Expected),
            []() -> Net::awaitable<void>
            {
                throw std::runtime_error("identity propagation");
                co_return;
            }());
        ASSERT_TRUE(Submitted);

        const auto Failure = RunDrain(Ioc, Control.Drain());

        ASSERT_TRUE(Failure);
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
        Prism::Runtime::SessionControl Control(Ioc.get_executor());
        std::atomic<std::size_t> CancelCalls{0};
        std::atomic<std::size_t> CloseCalls{0};
        std::atomic<std::size_t> MetricsCalls{0};
        std::atomic<std::size_t> CallbackEntries{0};
        std::atomic<std::size_t> InCallback{0};
        std::atomic<bool> ConcurrentCallbacks{false};
        std::atomic<bool> HoldCallbacks{true};
        const CallbackObservation Observation{
            CallbackEntries, InCallback, ConcurrentCallbacks, HoldCallbacks};

        ASSERT_TRUE(Control.AddCancelHook(
            [&Observation, &CancelCalls]
            {
                CancelCalls.fetch_add(1, std::memory_order_relaxed);
                Observation.Record();
            }));
        Control.SetMetricsHook(
            [&Observation, &MetricsCalls](const Prism::Runtime::SessionMetrics &)
            {
                MetricsCalls.fetch_add(1, std::memory_order_relaxed);
                Observation.Record();
            });

        std::vector<std::thread> IoThreads;
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            IoThreads.emplace_back([&Ioc] { Ioc.run(); });
        }

        std::thread CallerThread([&]
        {
            RunCancelCloseCallbacks(Control, CloseCalls, Observation);
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
        auto Context = Prism::Executor::ContextOwner::Create();
        Prism::Runtime::SessionControl Control;
        ASSERT_TRUE(Control.Bind(Context->Io.get_executor()));
        auto CloseExecuted = std::make_shared<std::atomic<bool>>(false);
        ASSERT_TRUE(Control.SetCloseAction(
            [CloseExecuted]() -> std::expected<void, Prism::Fault::Failure>
            {
                CloseExecuted->store(true, std::memory_order_release);
                return {};
            }));

        Context->Io.stop();
        EXPECT_FALSE(Control.CloseOnce());
        EXPECT_FALSE(CloseExecuted->load(std::memory_order_acquire));
        EXPECT_TRUE(Control.IsDrainBlocked());
        EXPECT_TRUE(Control.IsCloseDispatchFailed());
        EXPECT_TRUE(Control.Metrics().CloseDispatchFailed);
    }

TEST(TcpListenerLifecycle, ListenerTaskIdentityReachesSessionErrorHook)
    {
        Net::io_context Ioc;
        auto Observed =
            std::make_shared<std::optional<Prism::Lifecycle::TaskIdentity>>();
        auto FactoryWorker = std::make_shared<std::optional<Prism::WorkerId>>();
        auto ErrorReady = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto FactoryReady = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Control = std::make_shared<Prism::Runtime::SessionControl>();
        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            Prism::GenerationId{1});
        ListenerOptions.Factory = ListenerIdentityFactory{
            Control, FactoryWorker, Observed, FactoryReady, ErrorReady};
        ListenerOptions.WorkerCount = 4;
        Prism::Runtime::TcpListener Listener(std::move(ListenerOptions));

        auto StartResult = Prism::Fault::Code::GenericError;
        const auto Failure = RunCoro(
            Ioc,
            RunListenerIdentityScenario(Listener,
                ListenerIdentityProbe{Control, FactoryReady, ErrorReady, StartResult}));

        EXPECT_EQ(Failure, nullptr);
        EXPECT_EQ(StartResult, Prism::Fault::Code::Success);
        ASSERT_TRUE(FactoryWorker->has_value());
        ASSERT_TRUE(Observed->has_value());
        EXPECT_TRUE(static_cast<bool>((*Observed)->TaskId));
        EXPECT_TRUE(static_cast<bool>((*Observed)->SessionId));
        EXPECT_TRUE(static_cast<bool>((*Observed)->WorkerId));
        EXPECT_EQ((*Observed)->WorkerId, **FactoryWorker);
    }

TEST(TcpListenerLifecycle, FactoryExceptionNotifiesListenerFailure)
    {
        Net::io_context Ioc;
        auto FactoryReady = std::make_shared<Signal>(Ioc.get_executor(), 1U);
        auto FailureReady = std::make_shared<Signal>(Ioc.get_executor(), 1U);
        std::optional<Prism::Fault::Code> ObservedFailure;
        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            Prism::GenerationId{1});
        ListenerOptions.Factory = ThrowingListenerFactory{FactoryReady};
        ListenerOptions.OnFailure = [&ObservedFailure, FailureReady](
                                        const Prism::Fault::Code Code)
        {
            ObservedFailure = Code;
            (void)FailureReady->try_send(boost::system::error_code{});
        };
        Prism::Runtime::TcpListener Listener(std::move(ListenerOptions));

        const auto Failure = RunCoro(
            Ioc,
            RunListenerFactoryExceptionScenario(ListenerFactoryExceptionScenarioRequest{
                Ioc, Listener, FactoryReady, FailureReady}));

        EXPECT_EQ(Failure, nullptr);
        ASSERT_TRUE(ObservedFailure.has_value());
        EXPECT_EQ(*ObservedFailure, Prism::Fault::Code::GenericError);
    }

TEST(SessionControlLifecycle, CancelSealsFutureOperations)
    {
        Net::io_context Ioc;
        Prism::Runtime::SessionControl Control(Ioc.get_executor());
        bool Executed = false;

        EXPECT_TRUE(Control.Cancel());
        EXPECT_FALSE(Control.Start(
            Prism::Lifecycle::TaskRequest{},
            RunSealedOperation(Executed)));
        Ioc.run();
        EXPECT_FALSE(Executed);
    }

TEST(SessionControlLifecycle, WorkerRegistryBindingUsesIndependentChildScope)
    {
        Net::io_context Ioc;
        auto WorkerRegistry = std::make_shared<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Prism::Runtime::SessionControl First;
        Prism::Runtime::SessionControl Second;

        ASSERT_TRUE(First.Bind(Ioc.get_executor(), *WorkerRegistry));
        ASSERT_TRUE(Second.Bind(Ioc.get_executor(), *WorkerRegistry));
        ASSERT_TRUE(First.Cancel());

        auto Executed = std::make_shared<std::atomic<bool>>(false);
        ASSERT_TRUE(Second.Start(
            Prism::Lifecycle::TaskRequest{},
            SetFlag(Executed)));
        ASSERT_TRUE(RunDrain(Ioc, WorkerRegistry->Drain()));

        EXPECT_TRUE(Executed->load(std::memory_order_acquire));
        EXPECT_FALSE(WorkerRegistry->IsDrainBlocked());
    }

TEST(TaskRegistryLifecycle, ListsOnlyExactSessionAndReportsCancellationPolicy)
{
    Net::io_context Ioc;
    auto Registry = std::make_shared<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
    auto Ready = std::make_shared<Signal>(Ioc.get_executor(), 3U);

    auto CancellableRequest = Request(Identity(Prism::TaskId{}), [Ready]
    { (void)Ready->try_send(boost::system::error_code{}); });
    const auto Cancellable = Registry->SpawnTracked(
        std::move(CancellableRequest), WaitForSignal(Ready));
    ASSERT_TRUE(Cancellable);

    auto NonCancellableRequest = Request(Identity(Prism::TaskId{}));
    const auto NonCancellable = Registry->SpawnTracked(
        std::move(NonCancellableRequest), WaitForSignal(Ready));
    ASSERT_TRUE(NonCancellable);

    auto OtherSessionRequest = Request(Identity(Prism::TaskId{}));
    OtherSessionRequest.Context.SessionId = Prism::SessionId{8};
    const auto OtherSession = Registry->SpawnTracked(
        std::move(OtherSessionRequest), WaitForSignal(Ready));
    ASSERT_TRUE(OtherSession);

    std::optional<TaskPageResult> Listed;
    std::exception_ptr Failure;
    Net::co_spawn(Ioc, RunTaskRegistryListScenario(std::move(Registry), Ready),
        [&Listed, &Failure](std::exception_ptr Error, TaskPageResult Result)
        {
            Failure = std::move(Error);
            if (!Failure) Listed.emplace(std::move(Result));
        });
    Ioc.run();

    EXPECT_EQ(Failure, nullptr);
    ASSERT_TRUE(Listed.has_value());
    ASSERT_TRUE(*Listed);
    ASSERT_EQ(Listed->value().Items.size(), 2U);
    EXPECT_EQ(Listed->value().Items[0].Identity.SessionId, Prism::SessionId{7});
    EXPECT_EQ(Listed->value().Items[1].Identity.SessionId, Prism::SessionId{7});
    EXPECT_TRUE(Listed->value().Items[0].Cancellable);
    EXPECT_FALSE(Listed->value().Items[1].Cancellable);
}
