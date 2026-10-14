/**
 * @file SessionControlLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "SessionLifecycleTestSupport.hpp"
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>

#include <expected>

namespace
{

    using DrainOutcome = std::expected<void, Preview::Fault::Failure>;

    auto DrainWorkerRegistry(Preview::Lifecycle::TaskRegistry &Registry)
        -> Net::awaitable<void>
    {
        const auto Drained = co_await Registry.Drain();
        EXPECT_TRUE(Drained);
    }

    auto RunSubmittedIdentity(
        const std::shared_ptr<Preview::Runtime::SessionControl> &Control,
        const Preview::Lifecycle::TaskIdentity Submitted) -> Net::awaitable<void>
    {
        Preview::Lifecycle::TaskRequest Request;
        Request.Context = Preview::Lifecycle::TaskContext{
            Submitted.SessionId, Submitted.StreamId, Submitted.WorkerId,
            Submitted.Generation, Submitted.ParentTaskId};
        EXPECT_TRUE(Control->Start(
            std::move(Request),
            CheckCurrentIdentity(Control, Submitted)));
        const auto Drained = co_await Control->Drain();
        EXPECT_TRUE(Drained);
    }

    auto RunWorkerAdmissionIdentity(
        const std::shared_ptr<Preview::Runtime::SessionControl> &Control,
        Preview::Lifecycle::TaskRequest Request) -> Net::awaitable<void>
    {
        EXPECT_TRUE(Control->Start(
            std::move(Request),
            []() -> Net::awaitable<void> { co_return; }()));
        const auto Identity = Control->CurrentIdentity();
        EXPECT_EQ(Identity.SessionId, Preview::SessionId{301});
        EXPECT_EQ(Identity.WorkerId, Preview::WorkerId{4});
        EXPECT_EQ(Identity.Generation, Preview::GenerationId{17});
        EXPECT_TRUE(static_cast<bool>(Identity.TaskId));
        const auto Drained = co_await Control->Drain();
        EXPECT_TRUE(Drained);
    }

    auto RunThrowingOperation(
        const std::shared_ptr<Preview::Runtime::SessionControl> &Control) -> Net::awaitable<void>
    {
        const auto Started = Control->Start(
            Preview::Lifecycle::TaskRequest{},
            []() -> Net::awaitable<void>
            {
                throw std::runtime_error("preview operation failure");
                co_return;
            }());
        EXPECT_TRUE(Started);
        const auto Drained = co_await Control->Drain();
        EXPECT_TRUE(Drained);
    }

    struct DrainGraceScenario final
    {
        Net::io_context &Ioc;
        std::shared_ptr<Preview::Runtime::SessionControl> Control;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Release;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> DrainDone;
        std::shared_ptr<DrainOutcome> DrainResult;
        std::shared_ptr<std::exception_ptr> DrainException;
        std::shared_ptr<bool> OperationCompleted;
        std::shared_ptr<bool> DrainCompleted;
    };

    auto CompleteDrain(
        const std::shared_ptr<DrainGraceScenario> &Scenario,
        std::exception_ptr Failure,
        DrainOutcome Result) -> void
    {
        *Scenario->DrainException = std::move(Failure);
        *Scenario->DrainResult = std::move(Result);
        const bool Succeeded = !*Scenario->DrainException && *Scenario->DrainResult;
        *Scenario->DrainCompleted = Succeeded;
        auto Error = boost::system::error_code{};
        if (!Succeeded)
        {
            Error = boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }
        (void)Scenario->DrainDone->try_send(Error);
    }

    /**
     * @brief 按值保有取消与排空场景，直到非合作操作和 drain 回调真实完成。
     * @details Ioc 借用完整等待 RunCoro 的测试作用域；共享 channel 与结果由协程保活。
     */
    auto RunDrainGraceScenario(DrainGraceScenario Scenario) -> Net::awaitable<void>
    {
        auto Owner = std::make_shared<DrainGraceScenario>(std::move(Scenario));
        const auto Started = Owner->Control->Start(
            Preview::Lifecycle::TaskRequest{},
            WaitForReleaseAndMark(Owner->Release, Owner->OperationCompleted));
        EXPECT_TRUE(Started);
        const auto Canceled = Owner->Control->Cancel();
        EXPECT_TRUE(Canceled);
        Net::co_spawn(
            Owner->Ioc, Owner->Control->Drain(),
            [Owner](std::exception_ptr Failure, DrainOutcome Result)
            { CompleteDrain(Owner, std::move(Failure), std::move(Result)); });
        Net::steady_timer Grace(Owner->Ioc);
        Grace.expires_after(std::chrono::milliseconds(150));
        co_await Grace.async_wait(Net::use_awaitable);
        EXPECT_FALSE(*Owner->DrainCompleted);
        (void)Owner->Release->try_send(boost::system::error_code{});
        boost::system::error_code DrainError;
        co_await Owner->DrainDone->async_receive(
            Net::redirect_error(Net::use_awaitable, DrainError));
        EXPECT_FALSE(DrainError);
        EXPECT_TRUE(*Owner->DrainCompleted);
        EXPECT_TRUE(*Owner->DrainResult);
        EXPECT_FALSE(*Owner->DrainException);
        EXPECT_TRUE(*Owner->OperationCompleted);
    }

    struct NonCooperativeScenario final
    {
        Net::io_context &Ioc;
        std::shared_ptr<Preview::Runtime::SessionControl> Control;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Release;
        std::size_t &CancelCalls;
        std::size_t &CloseCalls;
    };

    /**
     * @brief 按值保有非合作操作的控制器与释放 channel，重复取消仍只交付一次。
     * @details Ioc 和计数器借用测试作用域；RunCoro 返回前完成取消、关闭与 drain。
     */
    auto RunNonCooperativeScenario(NonCooperativeScenario Scenario) -> Net::awaitable<void>
    {
        const auto CloseAction = Scenario.Control->SetCloseAction(
            [&CloseCalls = Scenario.CloseCalls]() -> DrainOutcome
            {
                ++CloseCalls;
                return {};
            });
        EXPECT_TRUE(CloseAction);
        const auto Started = Scenario.Control->Start(
            Preview::Lifecycle::TaskRequest{
                .Cancel = [&CancelCalls = Scenario.CancelCalls] { ++CancelCalls; }},
            WaitForRelease(Scenario.Release));
        EXPECT_TRUE(Started);
        const auto FirstCancel = Scenario.Control->Cancel();
        const auto RepeatedCancel = Scenario.Control->Cancel();
        EXPECT_TRUE(FirstCancel);
        EXPECT_TRUE(RepeatedCancel);
        Net::steady_timer Tick(Scenario.Ioc);
        Tick.expires_after(std::chrono::milliseconds(1));
        co_await Tick.async_wait(Net::use_awaitable);
        EXPECT_EQ(Scenario.CancelCalls, 1U);
        const auto FirstClose = Scenario.Control->CloseOnce();
        const auto RepeatedClose = Scenario.Control->CloseOnce();
        EXPECT_TRUE(FirstClose);
        EXPECT_TRUE(RepeatedClose);
        Net::co_spawn(
            Scenario.Ioc,
            [Control = Scenario.Control]() -> Net::awaitable<void>
            {
                const auto Drained = co_await Control->Drain();
                EXPECT_TRUE(Drained);
            },
            Net::detached);
        (void)Scenario.Release->try_send(boost::system::error_code{});
        const auto Drained = co_await Scenario.Control->Drain();
        EXPECT_TRUE(Drained);
        const auto Delivery = co_await Scenario.Control->AwaitDelivery();
        EXPECT_TRUE(Delivery);
    }

    struct IncrementCounter final
    {
        std::shared_ptr<std::size_t> Counter;

        auto operator()() const -> void
        {
            ++*Counter;
        }
    };

    struct RegistryShutdownRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::SessionRegistry> Registry;
        std::shared_ptr<Preview::Runtime::SessionControl> FirstControl;
        std::shared_ptr<Preview::Runtime::SessionControl> SecondControl;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> FirstRelease;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> SecondRelease;
        std::shared_ptr<std::size_t> FirstCancels;
        std::shared_ptr<std::size_t> SecondCancels;
        std::shared_ptr<bool> ShutdownCompleted;
    };

    auto MarkRegistryShutdown(
        std::shared_ptr<Preview::Runtime::SessionRegistry> Registry,
        std::shared_ptr<bool> ShutdownCompleted) -> Net::awaitable<void>
    {
        const auto Shutdown = co_await Registry->Shutdown();
        EXPECT_TRUE(Shutdown);
        *ShutdownCompleted = static_cast<bool>(Shutdown);
    }

    auto RunRegistryShutdown(RegistryShutdownRequest Request) -> Net::awaitable<void>
    {
        EXPECT_TRUE(Request.FirstControl->Start(
            Preview::Lifecycle::TaskRequest{
                .Cancel = IncrementCounter{Request.FirstCancels}},
            WaitForRelease(Request.FirstRelease)));
        EXPECT_TRUE(Request.SecondControl->Start(
            Preview::Lifecycle::TaskRequest{
                .Cancel = IncrementCounter{Request.SecondCancels}},
            WaitForRelease(Request.SecondRelease)));
        Net::co_spawn(
            Request.Executor,
            MarkRegistryShutdown(Request.Registry, Request.ShutdownCompleted),
            Net::detached);
        Net::steady_timer Pending(Request.Executor);
        Pending.expires_after(std::chrono::milliseconds(20));
        co_await Pending.async_wait(Net::use_awaitable);
        EXPECT_FALSE(*Request.ShutdownCompleted);
        EXPECT_EQ(*Request.FirstCancels, 1U);
        EXPECT_EQ(*Request.SecondCancels, 1U);
        (void)Request.FirstRelease->try_send(boost::system::error_code{});
        (void)Request.SecondRelease->try_send(boost::system::error_code{});
        const auto Shutdown = co_await Request.Registry->Shutdown();
        EXPECT_TRUE(Shutdown);
        EXPECT_TRUE(*Request.ShutdownCompleted);
    }

    auto ThrowTrackedFailure() -> Net::awaitable<void>
    {
        throw std::runtime_error("tracked failure");
        co_return;
    }

    struct RegistryFailureRequest final
    {
        std::shared_ptr<Preview::Runtime::SessionRegistry> Registry;
        std::shared_ptr<Preview::Runtime::SessionControl> Control;
    };

    auto RunRegistryFailure(RegistryFailureRequest Request) -> Net::awaitable<void>
    {
        EXPECT_TRUE(Request.Control->Start(
            Preview::Lifecycle::TaskRequest{}, ThrowTrackedFailure()));
        const auto Drained = co_await Request.Registry->Drain();
        EXPECT_TRUE(Drained);
        const auto FirstClose = Request.Control->CloseOnce();
        const auto RepeatedClose = Request.Control->CloseOnce();
        EXPECT_TRUE(FirstClose);
        EXPECT_TRUE(RepeatedClose);
        const auto Delivery = co_await Request.Control->AwaitDelivery();
        EXPECT_TRUE(Delivery);
    }

    auto RejectSession(Preview::Contract::StreamAcceptInput)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::BadAuth));
    }

    struct RejectingSessionFactory final
    {
        auto operator()(Preview::Runtime::SessionAdmission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            Preview::Runtime::SessionOptions Options;
            Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
                RejectSession);
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    struct RetainRegistrationState final
    {
        Preview::Runtime::TcpListener *Listener{nullptr};
        std::shared_ptr<ByteChannel> ErrorReady;
        std::shared_ptr<ByteChannel> MetricsReady;
        std::atomic<bool> ErrorSawLiveRegistration{false};
        std::atomic<bool> MetricsSawLiveRegistration{false};
        Preview::Fault::Failure ReportedFailure{};
        bool ErrorObserved{false};
        bool MetricsObserved{false};
    };

    struct RetainRegistrationErrorHook final
    {
        std::shared_ptr<RetainRegistrationState> State;

        auto operator()(std::uint64_t, Preview::Fault::Failure Failure) const
            -> void
        {
            State->ReportedFailure = Failure;
            State->ErrorSawLiveRegistration.store(
                State->Listener->Registry().Size() == 1U, std::memory_order_release);
            (void)State->ErrorReady->try_send(boost::system::error_code{});
        }
    };

    struct RetainRegistrationMetricsHook final
    {
        std::shared_ptr<RetainRegistrationState> State;

        auto operator()(std::uint64_t, const Preview::Runtime::SessionMetrics &Metrics) const
            -> void
        {
            if (Metrics.CloseCalls == 0U)
            {
                return;
            }
            State->MetricsSawLiveRegistration.store(
                State->Listener->Registry().Size() == 1U, std::memory_order_release);
            (void)State->MetricsReady->try_send(boost::system::error_code{});
        }
    };

    struct RetainRegistrationRequest final
    {
        Net::io_context *Ioc;
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::TcpListener> Listener;
        std::shared_ptr<RetainRegistrationState> State;
    };

    auto RunRetainRegistration(RetainRegistrationRequest Request)
        -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Listener->Start(
                      Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                  Preview::Fault::Code::Success);
        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code Error;
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Preview::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(Error);
        if (!Client)
        {
            Request.Listener->Stop();
            co_return;
        }
        Request.State->ErrorObserved = co_await WaitForSignalOrTimeout(
            Request.State->ErrorReady, *Request.Ioc);
        Request.State->MetricsObserved = co_await WaitForSignalOrTimeout(
            Request.State->MetricsReady, *Request.Ioc);
        const auto Shutdown = co_await Request.Listener->Shutdown();
        EXPECT_TRUE(Shutdown);
        (void)Client->Close();
    }

} // namespace

TEST(SessionControlLifecycle, ExposesSubmittedListenerTaskIdentity)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        Preview::Lifecycle::TaskIdentity Submitted;
        Submitted.SessionId = Preview::SessionId{101};
        Submitted.WorkerId = Preview::WorkerId{3};

        Preview::Testing::RunCoro(Ioc, RunSubmittedIdentity(Control, Submitted));
    }

TEST(SessionControlLifecycle, WorkerAdmissionIdentityStaysWithChildScope)
    {
        Net::io_context Ioc;
        Preview::Lifecycle::TaskRegistry WorkerRegistry(Ioc.get_executor());
        auto Control = std::make_shared<Preview::Runtime::SessionControl>();
        ASSERT_TRUE(Control->Bind(Ioc.get_executor(), WorkerRegistry));

        Preview::Lifecycle::TaskRequest Request;
        Request.Context.SessionId = Preview::SessionId{301};
        Request.Context.WorkerId = Preview::WorkerId{4};
        Request.Context.Generation = Preview::GenerationId{17};

        Preview::Testing::RunCoro(Ioc, RunWorkerAdmissionIdentity(Control, std::move(Request)));

        EXPECT_FALSE(Control->IsCancelled());
        const auto Canceled = Control->Cancel();
        EXPECT_TRUE(Canceled);
        EXPECT_TRUE(Control->IsCancelled());
        const auto WorkerTask = WorkerRegistry.SpawnTracked(
            Preview::Lifecycle::TaskRequest{},
            []() -> Net::awaitable<void> { co_return; }());
        ASSERT_TRUE(WorkerTask);
        Ioc.restart();
        Preview::Testing::RunCoro(Ioc, DrainWorkerRegistry(WorkerRegistry));
    }

TEST(SessionControlLifecycle, DrainWaitsPastConfiguredGraceUntilLoserCompletes)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        auto DrainDone = MakeReleaseChannel(Ioc.get_executor());
        auto DrainResult = std::make_shared<DrainOutcome>(
            std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::GenericError}));
        auto DrainException = std::make_shared<std::exception_ptr>();
        auto OperationCompleted = std::make_shared<bool>(false);
        auto DrainCompleted = std::make_shared<bool>(false);

        RunCoro(Ioc, RunDrainGraceScenario(
            DrainGraceScenario{Ioc, Control, Release, DrainDone, DrainResult, DrainException,
                OperationCompleted, DrainCompleted}));
    }

TEST(SessionControlLifecycle, ThrowingOperationReportsErrorAndDrains)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        std::size_t ErrorCalls = 0;
        Preview::Fault::Failure ReportedFailure{};
        Control->SetErrorHook(
            [&ErrorCalls, &ReportedFailure](Preview::Fault::Failure Failure)
            {
                ++ErrorCalls;
                ReportedFailure = Failure;
            });

        RunCoro(Ioc, RunThrowingOperation(Control));

        EXPECT_EQ(ErrorCalls, 1U);
        EXPECT_EQ(ReportedFailure.Code, Preview::Fault::Code::IoError);
        EXPECT_FALSE(ReportedFailure.Native);
    }

TEST(SessionControlLifecycle, NonCooperativeCancelIsSingleShotAndCloseIsExactlyOnce)
    {
        Net::io_context Ioc;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto Release = MakeReleaseChannel(Ioc.get_executor());
        std::size_t CancelCalls = 0;
        std::size_t CloseCalls = 0;

        RunCoro(Ioc, RunNonCooperativeScenario(
            NonCooperativeScenario{Ioc, Control, Release, CancelCalls, CloseCalls}));

        EXPECT_EQ(CancelCalls, 1U);
        EXPECT_EQ(CloseCalls, 1U);
        EXPECT_EQ(Control->Metrics().CancelRequests, 1U);
        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);
    }

TEST(SessionRegistryLifecycle, ShutdownCancelsAndDrainsAllRegisteredSessions)
    {
        Net::io_context Ioc;
        auto Registry = std::make_shared<Preview::Runtime::SessionRegistry>();
        auto FirstControl = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto SecondControl = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto FirstRelease = MakeReleaseChannel(Ioc.get_executor());
        auto SecondRelease = MakeReleaseChannel(Ioc.get_executor());
        auto FirstCancels = std::make_shared<std::size_t>(0);
        auto SecondCancels = std::make_shared<std::size_t>(0);
        auto FirstRegistration = Registry->Register(MakeInfo(1), FirstControl);
        auto SecondRegistration = Registry->Register(MakeInfo(2), SecondControl);
        ASSERT_TRUE(FirstRegistration);
        ASSERT_TRUE(SecondRegistration);

        auto ShutdownCompleted = std::make_shared<bool>(false);
        RunCoro(Ioc, RunRegistryShutdown(RegistryShutdownRequest{
                            Ioc.get_executor(), Registry, FirstControl, SecondControl,
                            FirstRelease, SecondRelease, FirstCancels, SecondCancels,
                            ShutdownCompleted}));

        EXPECT_EQ(*FirstCancels, 1U);
        EXPECT_EQ(*SecondCancels, 1U);
        EXPECT_EQ(Registry->Size(), 0U);
        FirstRegistration.Reset();
        SecondRegistration.Reset();
        EXPECT_EQ(Registry->Size(), 0U);
    }

TEST(SessionRegistryLifecycle, ShutdownDrainsRegisteredOwners)
    {
        Net::io_context Ioc;
        auto Registry = std::make_shared<Preview::Runtime::SessionRegistry>();
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto Registration = Registry->Register(MakeInfo(99), Control);
        ASSERT_TRUE(Registration);
        EXPECT_EQ(Registry->Size(), 1U);

        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const auto Shutdown = co_await Registry->Shutdown();
                EXPECT_TRUE(Shutdown);
            });

        EXPECT_EQ(Registry->Size(), 0U);
        Registration.Reset();
        EXPECT_EQ(Registry->Size(), 0U);
    }

TEST(SessionRegistryLifecycle, ReportsOperationFailureThroughExplicitHooks)
    {
        Net::io_context Ioc;
        auto Registry = std::make_shared<Preview::Runtime::SessionRegistry>();
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        auto ErrorCalls = std::make_shared<std::size_t>(0);
        auto MetricCalls = std::make_shared<std::size_t>(0);
        auto ErrorFailure = std::make_shared<Preview::Fault::Failure>();
        Registry->SetErrorHook(
            [ErrorCalls, ErrorFailure](std::uint64_t, Preview::Fault::Failure Failure)
            {
                ++*ErrorCalls;
                *ErrorFailure = Failure;
            });
        Registry->SetMetricsHook(
            [MetricCalls](std::uint64_t, const Preview::Runtime::SessionMetrics &)
            { ++*MetricCalls; });
        const auto CloseAction = Control->SetCloseAction(
            []() -> DrainOutcome { return {}; });
        ASSERT_TRUE(CloseAction);
        auto Registration = Registry->Register(MakeInfo(7), Control);
        ASSERT_TRUE(Registration);

        RunCoro(Ioc, RunRegistryFailure(RegistryFailureRequest{Registry, Control}));

        EXPECT_EQ(*ErrorCalls, 1U);
        EXPECT_EQ(ErrorFailure->Code, Preview::Fault::Code::IoError);
        EXPECT_FALSE(ErrorFailure->Native);
        EXPECT_GT(*MetricCalls, 0U);
        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);
        Registration.Reset();
    }

TEST(TcpListenerLifecycle, RetainsRegistrationUntilFinalHookDelivery)
    {
        Net::io_context Ioc;
        auto ErrorReady = MakeReleaseChannel(Ioc.get_executor());
        auto MetricsReady = MakeReleaseChannel(Ioc.get_executor());
        auto State = std::make_shared<RetainRegistrationState>();
        State->ErrorReady = ErrorReady;
        State->MetricsReady = MetricsReady;
        auto Listener = std::make_shared<Preview::Runtime::TcpListener>(
            Preview::Runtime::TcpListener::Options{
            .Executor = Ioc.get_executor(),
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{1}),
            .Factory = RejectingSessionFactory{}});
        State->Listener = Listener.get();
        Listener->Registry().SetErrorHook(
            RetainRegistrationErrorHook{State});
        Listener->Registry().SetMetricsHook(
            RetainRegistrationMetricsHook{State});

        // RunCoro 完整等待 request；State->Listener 只借用本调用期间的 shared owner。
        RunCoro(Ioc, RunRetainRegistration(RetainRegistrationRequest{
                            &Ioc, Ioc.get_executor(), Listener, State}));

        EXPECT_TRUE(State->ErrorObserved);
        EXPECT_TRUE(State->MetricsObserved);
        EXPECT_TRUE(State->ErrorSawLiveRegistration.load(std::memory_order_acquire));
        EXPECT_TRUE(State->MetricsSawLiveRegistration.load(std::memory_order_acquire));
        EXPECT_EQ(State->ReportedFailure.Code, Preview::Fault::Code::AuthFailed);
        EXPECT_FALSE(State->ReportedFailure.Native);
        EXPECT_EQ(Listener->Registry().Size(), 0U);
    }

struct CrossExecutorDeliveryScenario final
{
    Net::io_context Caller;
    Net::io_context Worker;
    std::shared_ptr<Preview::Lifecycle::TaskRegistry> WorkerRegistry;
    std::shared_ptr<Preview::Runtime::SessionControl> Control;
    std::shared_ptr<Net::cancellation_signal> CallerCancellation;
    Preview::Runtime::SessionRegistry Registry;
    std::shared_ptr<ConcurrentSignal> ErrorReady;
    std::shared_ptr<ConcurrentSignal> CloseReady;
    std::shared_ptr<ConcurrentSignal> MetricsReady;
    Preview::Runtime::SessionRegistry::Registration Registration;
    std::shared_ptr<Net::steady_timer> Watchdog;
    std::atomic<bool> AckReturned{false};
    std::atomic<bool> CloseCallbackDone{false};
    std::atomic<bool> ObserverSawAckEarly{false};
    std::atomic<bool> FinalMetricsSeen{false};
    std::atomic<bool> HookOrderError{false};
    std::atomic<int> HookStage{0};
    bool ErrorObserved{false};
    bool CloseObserved{false};
    bool MetricsObserved{false};
    bool Ack{false};
    Preview::Fault::Failure ReportedFailure{};
    Preview::Fault::Failure DeliveryFailure{};
    std::atomic<bool> Completed{false};
    std::atomic<bool> TimedOut{false};
    std::exception_ptr Failure;

    CrossExecutorDeliveryScenario()
        : WorkerRegistry(std::make_shared<Preview::Lifecycle::TaskRegistry>(Worker.get_executor())),
          Control(std::make_shared<Preview::Runtime::SessionControl>()),
          CallerCancellation(std::make_shared<Net::cancellation_signal>()),
          ErrorReady(MakeConcurrentSignal(Caller.get_executor())),
          CloseReady(MakeConcurrentSignal(Caller.get_executor())),
          MetricsReady(MakeConcurrentSignal(Caller.get_executor()))
    {
    }

    auto Setup() -> bool
    {
        if (!Control->Bind(Worker.get_executor(), *WorkerRegistry))
        {
            return false;
        }
        const auto CloseAction = Control->SetCloseAction(
            [this]() -> DrainOutcome
            {
                OnClose();
                return {};
            });
        if (!CloseAction)
        {
            return false;
        }
        Registry.SetErrorHook([this](std::uint64_t Id, Preview::Fault::Failure Error)
        { OnError(Id, Error); });
        Registry.SetMetricsHook([this](auto Id, const auto &Metrics)
        { OnMetrics(Id, Metrics); });
        auto Value = Registry.Register(MakeInfo(503), Control);
        if (!Value)
        {
            return false;
        }
        Registration = std::move(Value);
        return true;
    }

    auto OnError(std::uint64_t, Preview::Fault::Failure Error) -> void
    {
        ReportedFailure = Error;
        int Expected = 0;
        if (!HookStage.compare_exchange_strong(
                Expected, 1, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            HookOrderError.store(true, std::memory_order_release);
        }
        if (AckReturned.load(std::memory_order_acquire))
        {
            ObserverSawAckEarly.store(true, std::memory_order_release);
        }
        (void)ErrorReady->try_send(boost::system::error_code{});
    }

    auto OnMetrics(std::uint64_t, const Preview::Runtime::SessionMetrics &Metrics) -> void
    {
        if (!CloseCallbackDone.load(std::memory_order_acquire))
        {
            return;
        }
        if (AckReturned.load(std::memory_order_acquire))
        {
            ObserverSawAckEarly.store(true, std::memory_order_release);
        }
        if (!FinalMetricsSeen.exchange(true, std::memory_order_acq_rel))
        {
            int Expected = 2;
            if (!HookStage.compare_exchange_strong(
                    Expected, 3, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                HookOrderError.store(true, std::memory_order_release);
            }
        }
        (void)MetricsReady->try_send(boost::system::error_code{});
        (void)Metrics;
    }

    auto OnClose() -> void
    {
        int Expected = 1;
        if (!HookStage.compare_exchange_strong(
                Expected, 2, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            HookOrderError.store(true, std::memory_order_release);
        }
        if (AckReturned.load(std::memory_order_acquire))
        {
            ObserverSawAckEarly.store(true, std::memory_order_release);
        }
        CloseCallbackDone.store(true, std::memory_order_release);
        (void)CloseReady->try_send(boost::system::error_code{});
    }

    auto RunWatchdog() -> Net::awaitable<void>
    {
        Watchdog->expires_after(std::chrono::seconds(2));
        boost::system::error_code ErrorCode;
        co_await Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (!ErrorCode && !Completed.load(std::memory_order_acquire))
        {
            TimedOut.store(true, std::memory_order_release);
            Caller.stop();
            Worker.stop();
        }
    }

    auto StoreFailure(std::exception_ptr Error) -> void
    {
        if (Error)
        {
            Failure = std::move(Error);
        }
    }

    auto RunControl() -> Net::awaitable<void>
    {
        Control->ReportError(
            Preview::Fault::Failure{Preview::Fault::Code::IoError});
        const auto CloseSubmitted = Control->CloseOnce();
        EXPECT_TRUE(CloseSubmitted);
        ErrorObserved = co_await WaitForSignalOrTimeout(ErrorReady, Caller);
        const auto Canceled = Control->Cancel();
        EXPECT_TRUE(Canceled);
        CallerCancellation->emit(Net::cancellation_type::all);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const auto Delivery = co_await Control->AwaitDelivery();
        Ack = static_cast<bool>(Delivery);
        if (!Delivery)
        {
            DeliveryFailure = Delivery.error();
        }
        AckReturned.store(true, std::memory_order_release);
        CloseObserved = co_await WaitForSignalOrTimeout(CloseReady, Caller);
        MetricsObserved = co_await WaitForSignalOrTimeout(MetricsReady, Caller);
        EXPECT_TRUE(Ack);
        EXPECT_TRUE(DeliveryFailure.Succeeded());
        EXPECT_EQ(Registry.Size(), 1U);
        Registration.Reset();
        EXPECT_EQ(Registry.Size(), 0U);
        Completed.store(true, std::memory_order_release);
        (void)Watchdog->cancel();
    }

    auto Run() -> void
    {
        ASSERT_TRUE(Setup());
        Watchdog = std::make_shared<Net::steady_timer>(Caller);
        auto WorkerWork = Net::make_work_guard(Worker);
        std::thread WorkerThread([this] { Worker.run(); });
        Net::co_spawn(Caller, RunWatchdog(),
            [this](std::exception_ptr Error) { StoreFailure(std::move(Error)); });
        Net::co_spawn(
            Caller,
            RunControl(),
            Net::bind_cancellation_slot(CallerCancellation->slot(),
                [this](std::exception_ptr Error) { StoreFailure(std::move(Error)); }));
        std::thread CallerThread([this] { Caller.run(); });
        CallerThread.join();
        WorkerWork.reset();
        Worker.stop();
        WorkerThread.join();

        EXPECT_FALSE(TimedOut.load(std::memory_order_acquire));
        EXPECT_EQ(Failure, nullptr);
        EXPECT_TRUE(ErrorObserved);
        EXPECT_TRUE(CloseObserved);
        EXPECT_TRUE(MetricsObserved);
        EXPECT_EQ(ReportedFailure.Code, Preview::Fault::Code::IoError);
        EXPECT_FALSE(ReportedFailure.Native);
        EXPECT_TRUE(DeliveryFailure.Succeeded());
        EXPECT_FALSE(ObserverSawAckEarly.load(std::memory_order_acquire));
        EXPECT_FALSE(HookOrderError.load(std::memory_order_acquire));
        EXPECT_EQ(HookStage.load(std::memory_order_acquire), 3);
        EXPECT_FALSE(Control->IsDrainBlocked());
    }
};

TEST(SessionControlLifecycle, CrossExecutorDeliveryWaitsForCancellationAndFinalHooks)
{
    CrossExecutorDeliveryScenario Scenario;
    Scenario.Run();
}

