/**
 * @file TaskOwnershipLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TaskLifecycleTestSupport.hpp"
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <boost/asio/this_coro.hpp>

namespace
{
    /** @brief 保存同一 listener 身份检查的控制器、错误通知和启动观察槽。 */
    struct ListenerIdentityProbe final
    {
        std::shared_ptr<Preview::Runtime::SessionControl> Control;
        std::shared_ptr<Signal> ErrorReady;
        Preview::Fault::Code &StartResult;
    };

    /** @brief 为同一 listener 的错误通知保存身份观察者和实际控制器。 */
    struct ListenerIdentityFactory final
    {
        std::shared_ptr<Preview::Runtime::SessionControl> Control;
        std::shared_ptr<std::optional<std::size_t>> FactoryWorker;
        std::shared_ptr<std::optional<Preview::Lifecycle::TaskIdentity>> Observed;
        std::shared_ptr<Signal> ErrorReady;

        auto operator()(Preview::Runtime::SessionAdmission Admission)
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            *FactoryWorker = static_cast<std::size_t>(Admission.Worker.Value() - 1U);
            Control->SetErrorHook(Preview::Runtime::SessionControl::IdentityErrorHook{
                [Observed = Observed, ErrorReady = ErrorReady](
                    const Preview::Lifecycle::TaskIdentity &IdentityValue,
                     Preview::Fault::Failure)
                {
                    *Observed = IdentityValue;
                    (void)ErrorReady->try_send(boost::system::error_code{});
                }});
            Preview::Runtime::SessionOptions Options;
            Options.Control = Control;
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    /**
     * @brief 在当前 executor 验证 listener 的任务身份并等待 listener/control 关闭。
     * @details Listener 和启动观察槽由调用测试保持到 run 返回；通知与 Control
     *          在协程内拥有。错误连接也等待 Shutdown，不留下 accept loop。
     */
    auto RunListenerIdentityScenario(Preview::Runtime::TcpListener &Listener,
        ListenerIdentityProbe Probe) -> Net::awaitable<void>
    {
        Probe.StartResult = co_await Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Probe.StartResult, Preview::Fault::Code::Success);
        if (Probe.StartResult != Preview::Fault::Code::Success)
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
        Preview::Runtime::SessionControl &Control,
        std::atomic<std::size_t> &CloseCalls,
        const CallbackObservation &Observation) -> void
    {
        const auto Installed = Control.SetCloseAction(
            [&CloseCalls, &Observation]()
            -> std::expected<void, Preview::Fault::Failure>
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

    using TaskPageResult = std::expected<Preview::Lifecycle::TaskRegistryListPage,
                                         Preview::Fault::Failure>;

    /** @brief 枚举准确 session 的任务快照，再经真实 registry drain 释放测试 owner。 */
    auto RunTaskRegistryListScenario(
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Registry,
        std::shared_ptr<Signal> Ready) -> Net::awaitable<TaskPageResult>
    {
        auto Listed = co_await Registry->ListTasks(
            Preview::Lifecycle::TaskRegistryListRequest{
                Preview::SessionId{7}, Preview::WorkerId{11}, Preview::GenerationId{13}, 0U, 10U});
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
        Preview::Runtime::SessionControl Control(Ioc.get_executor());
        std::optional<Preview::Lifecycle::TaskIdentity> Observed;
        Control.SetErrorHook(
            Preview::Runtime::SessionControl::IdentityErrorHook{
                [&Observed](const Preview::Lifecycle::TaskIdentity &IdentityValue,
                             Preview::Fault::Failure)
            { Observed = IdentityValue; }});

        const auto Expected = Identity(Preview::TaskId{});
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
        Preview::Runtime::SessionControl Control(Ioc.get_executor());
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
            [&Observation, &MetricsCalls](const Preview::Runtime::SessionMetrics &)
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
        auto Context = Preview::Executor::ContextOwner::Create();
        Preview::Runtime::SessionControl Control;
        ASSERT_TRUE(Control.Bind(Context->Io.get_executor()));
        auto CloseExecuted = std::make_shared<std::atomic<bool>>(false);
        ASSERT_TRUE(Control.SetCloseAction(
            [CloseExecuted]() -> std::expected<void, Preview::Fault::Failure>
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
            std::make_shared<std::optional<Preview::Lifecycle::TaskIdentity>>();
        auto FactoryWorker = std::make_shared<std::optional<std::size_t>>();
        auto ErrorReady = std::make_shared<Signal>(Ioc.get_executor(), 1);
        auto Control = std::make_shared<Preview::Runtime::SessionControl>();
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            Preview::GenerationId{1});
        ListenerOptions.Factory = ListenerIdentityFactory{
            Control, FactoryWorker, Observed, ErrorReady};
        ListenerOptions.WorkerCount = 4;
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        auto StartResult = Preview::Fault::Code::GenericError;
        const auto Failure = RunCoro(
            Ioc,
            RunListenerIdentityScenario(Listener,
                ListenerIdentityProbe{Control, ErrorReady, StartResult}));

        EXPECT_EQ(Failure, nullptr);
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

        EXPECT_TRUE(Control.Cancel());
        EXPECT_FALSE(Control.Start(
            Preview::Lifecycle::TaskRequest{},
            RunSealedOperation(Executed)));
        Ioc.run();
        EXPECT_FALSE(Executed);
    }

TEST(SessionControlLifecycle, WorkerRegistryBindingUsesIndependentChildScope)
    {
        Net::io_context Ioc;
        auto WorkerRegistry = std::make_shared<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Preview::Runtime::SessionControl First;
        Preview::Runtime::SessionControl Second;

        ASSERT_TRUE(First.Bind(Ioc.get_executor(), *WorkerRegistry));
        ASSERT_TRUE(Second.Bind(Ioc.get_executor(), *WorkerRegistry));
        ASSERT_TRUE(First.Cancel());

        auto Executed = std::make_shared<std::atomic<bool>>(false);
        ASSERT_TRUE(Second.Start(
            Preview::Lifecycle::TaskRequest{},
            SetFlag(Executed)));
        ASSERT_TRUE(RunDrain(Ioc, WorkerRegistry->Drain()));

        EXPECT_TRUE(Executed->load(std::memory_order_acquire));
        EXPECT_FALSE(WorkerRegistry->IsDrainBlocked());
    }

TEST(TaskRegistryLifecycle, ListsOnlyExactSessionAndReportsCancellationPolicy)
{
    Net::io_context Ioc;
    auto Registry = std::make_shared<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
    auto Ready = std::make_shared<Signal>(Ioc.get_executor(), 3U);

    auto CancellableRequest = Request(Identity(Preview::TaskId{}), [Ready]
    { (void)Ready->try_send(boost::system::error_code{}); });
    const auto Cancellable = Registry->SpawnTracked(
        std::move(CancellableRequest), WaitForSignal(Ready));
    ASSERT_TRUE(Cancellable);

    auto NonCancellableRequest = Request(Identity(Preview::TaskId{}));
    const auto NonCancellable = Registry->SpawnTracked(
        std::move(NonCancellableRequest), WaitForSignal(Ready));
    ASSERT_TRUE(NonCancellable);

    auto OtherSessionRequest = Request(Identity(Preview::TaskId{}));
    OtherSessionRequest.Context.SessionId = Preview::SessionId{8};
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
    EXPECT_EQ(Listed->value().Items[0].Identity.SessionId, Preview::SessionId{7});
    EXPECT_EQ(Listed->value().Items[1].Identity.SessionId, Preview::SessionId{7});
    EXPECT_TRUE(Listed->value().Items[0].Cancellable);
    EXPECT_FALSE(Listed->value().Items[1].Cancellable);
}
