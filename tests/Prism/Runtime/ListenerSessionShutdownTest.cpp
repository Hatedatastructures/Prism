/**
 * @file ListenerSessionShutdownTest.cpp
 * @brief 验证活动 Session 在 Listener 停止时真实退栈并关闭传输。
 */
#include "ListenerTestSupport.hpp"
#include "SessionLifecycleTestSupport.hpp"

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <chrono>
#include <expected>
#include <variant>

#include <Prism/Foundation/Memory/BytePool.hpp>

namespace
{
    using HeldAdmissionEvents = ListenerTestEvents;

    auto ReceiveHeldAdmissionEvent(HeldAdmissionEvents &Events)
        -> Net::awaitable<bool>
    {
        boost::system::error_code Error;
        co_await Events.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        co_return !Error;
    }
    struct ActiveSessionShutdownState final
    {
        explicit ActiveSessionShutdownState(Net::any_io_executor Executor)
            : Entered(std::make_shared<HeldAdmissionEvents>(Executor, 1)),
              PayloadConsumed(std::make_shared<HeldAdmissionEvents>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<HeldAdmissionEvents> Entered;
        std::shared_ptr<HeldAdmissionEvents> PayloadConsumed;
        std::atomic<bool> PayloadObserved{false};
        Prism::Fault::Code StartResult{Prism::Fault::Code::GenericError};
        Prism::Fault::Code ShutdownResult{Prism::Fault::Code::GenericError};
        bool ShutdownTimedOut{false};
        bool ClientClosed{false};
    };

    struct ListenerShutdownOutcome final
    {
        bool TimedOut{false};
        std::expected<void, Prism::Fault::Failure> Result;
        std::shared_ptr<ListenerOperationCompletion> Completion;
    };

    /** @brief 以本地 watchdog 有界等待 listener shutdown。 */
    auto ShutdownListenerGuarded(
        Net::io_context &IoContext,
        const std::shared_ptr<Prism::Runtime::TcpListener> &Listener)
        -> Net::awaitable<ListenerShutdownOutcome>
    {
        const auto Completion = StartListenerOperation(IoContext, Listener->Shutdown());
        const auto Wait = co_await WaitForListenerOperationGuarded(
            IoContext, Completion, std::chrono::seconds(3));
        if (Wait.TimedOut)
        {
            Listener->Stop();
            co_return ListenerShutdownOutcome{
                true,
                std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Timeout}),
                Completion};
        }
        co_return ListenerShutdownOutcome{
            false, std::move(Wait.Result), Completion};
    }

    /** @brief 在调用方关闭客户端后，再有界等待 listener 的独立关闭任务退栈。 */
    auto WaitForShutdownCompletionGuarded(
        Net::io_context &IoContext,
        const std::shared_ptr<ListenerOperationCompletion> &Completion)
        -> Net::awaitable<bool>
    {
        const auto Wait = co_await WaitForListenerOperationGuarded(
            IoContext, Completion, std::chrono::seconds(3));
        co_return !Wait.TimedOut && static_cast<bool>(Wait.Result);
    }

    /** @brief 探针提前失败时请求关闭，并在必要时等到限定清理期限。 */
    auto FinishListenerShutdownAfterProbeFailure(
        Net::io_context &IoContext,
        const std::shared_ptr<Prism::Runtime::TcpListener> &Listener,
        const Prism::SharedTransmission &Client = {})
        -> Net::awaitable<ListenerShutdownOutcome>
    {
        ListenerTransmissionCloseAttempt CloseAttempt;
        if (Client) CloseAttempt = StartListenerTransmissionClose(IoContext, Client);
        const auto Shutdown = co_await ShutdownListenerGuarded(IoContext, Listener);
        const bool ShutdownRetired = Shutdown.TimedOut
            ? co_await WaitForShutdownCompletionGuarded(IoContext, Shutdown.Completion)
            : static_cast<bool>(Shutdown.Result);
        const bool ClientRetired = !Client ||
            co_await WaitForListenerTransmissionCloseGuarded(
                IoContext, CloseAttempt, std::chrono::seconds(3));
        if (!ShutdownRetired || !ClientRetired) IoContext.stop();
        co_return Shutdown;
    }

    /** @brief 消费一字节后继续等待，供 Listener shutdown 关闭活动 Session。 */
    auto AwaitActiveSessionShutdown(
        Prism::SharedTransmission Inbound,
        std::shared_ptr<ActiveSessionShutdownState> State)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        (void)State->Entered->try_send(boost::system::error_code{});
        std::array<std::byte, 1> Payload{};
        const auto Read = co_await Inbound->ReadExact(Payload);
        if (Read.Failure.Failed() || Read.Bytes != Payload.size())
        {
            (void)Inbound->Close();
            co_return std::unexpected(
                Prism::Contract::FailureFromProtocolError(Prism::Error::Canceled));
        }
        State->PayloadObserved.store(Payload[0] == std::byte{0x2A}, std::memory_order_release);
        (void)State->PayloadConsumed->try_send(boost::system::error_code{});
        std::array<std::byte, 1> Pending{};
        (void)co_await Inbound->ReadExact(Pending);
        (void)Inbound->Close();
        co_return std::unexpected(
            Prism::Contract::FailureFromProtocolError(Prism::Error::Canceled));
    }

    struct ActiveSessionShutdownFactory final
    {
        std::shared_ptr<ActiveSessionShutdownState> State;
        Prism::Runtime::WorkerGroup *Workers{nullptr};

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            auto Options = MakeListenerWorkerSessionOptions(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.SourceIp = std::move(Admission.SourceIp);
            Options.Services->Generation = Admission.Generation;
            Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
                [State = State](Prism::Contract::StreamAcceptInput Input)
                {
                    return AwaitActiveSessionShutdown(std::move(Input.Inbound), State);
                });
            return std::make_shared<Prism::Runtime::Session>(std::move(Options));
        }
    };

    /** @brief 保持已消费数据的 Session 活动，验证 Listener 关停完成并关闭客户端。 */
    auto RunActiveSessionShutdownProbe(
        Net::io_context &IoContext,
        const std::shared_ptr<Prism::Runtime::TcpListener> &Listener,
        const std::shared_ptr<ActiveSessionShutdownState> &State) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator||;
        State->StartResult = co_await Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        if (State->StartResult != Prism::Fault::Code::Success)
        {
            co_return;
        }
        Prism::Network::Dialer::Dialer Dialer(IoContext.get_executor());
        Net::steady_timer ConnectWatchdog(IoContext);
        ConnectWatchdog.expires_after(std::chrono::seconds(3));
        const auto ConnectWait = co_await (
            Dialer.Connect(
                {*Prism::Network::ParseHost("127.0.0.1"), Listener->LocalEndpoint().port()}) ||
            ExpireListenerTestWatchdog(ConnectWatchdog));
        if (ConnectWait.index() != 0U)
        {
            State->ShutdownResult = Prism::Fault::Code::Timeout;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(IoContext, Listener);
            State->ShutdownTimedOut = Cleanup.TimedOut;
            co_return;
        }
        auto Dialed = std::get<0>(ConnectWait);
        if (!Dialed)
        {
            State->ShutdownResult = Dialed.error().Code;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(IoContext, Listener);
            State->ShutdownTimedOut = Cleanup.TimedOut;
            co_return;
        }
        auto Client = std::move(*Dialed);
        Net::steady_timer EnteredWatchdog(IoContext);
        EnteredWatchdog.expires_after(std::chrono::seconds(3));
        const auto EnteredWait = co_await (
            ReceiveHeldAdmissionEvent(*State->Entered) ||
            ExpireListenerTestWatchdog(EnteredWatchdog));
        if (EnteredWait.index() != 0U || !std::get<0>(EnteredWait))
        {
            State->ShutdownResult = Prism::Fault::Code::Timeout;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(
                IoContext, Listener, Client);
            State->ShutdownTimedOut = Cleanup.TimedOut;
            co_return;
        }
        const std::array<std::byte, 1> Payload{std::byte{0x2A}};
        Net::steady_timer WriteWatchdog(IoContext);
        WriteWatchdog.expires_after(std::chrono::seconds(3));
        const auto WriteWait = co_await (
            Client->WriteSome(Payload) || ExpireListenerTestWatchdog(WriteWatchdog));
        if (WriteWait.index() != 0U)
        {
            State->ShutdownResult = Prism::Fault::Code::Timeout;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(
                IoContext, Listener, Client);
            State->ShutdownTimedOut = Cleanup.TimedOut;
            co_return;
        }
        const auto Written = std::get<0>(WriteWait);
        if (Written.Failure.Failed() || Written.Bytes != Payload.size())
        {
            State->ShutdownResult = Written.Failure.Failed()
                ? Written.Failure.Code : Prism::Fault::Code::IoError;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(
                IoContext, Listener, Client);
            State->ShutdownTimedOut = Cleanup.TimedOut;
            co_return;
        }
        Net::steady_timer ConsumedWatchdog(IoContext);
        ConsumedWatchdog.expires_after(std::chrono::seconds(3));
        const auto ConsumedWait = co_await (
            ReceiveHeldAdmissionEvent(*State->PayloadConsumed) ||
            ExpireListenerTestWatchdog(ConsumedWatchdog));
        if (ConsumedWait.index() != 0U || !std::get<0>(ConsumedWait))
        {
            State->ShutdownResult = Prism::Fault::Code::Timeout;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(
                IoContext, Listener, Client);
            State->ShutdownTimedOut = Cleanup.TimedOut;
            co_return;
        }
        const auto Shutdown = co_await ShutdownListenerGuarded(IoContext, Listener);
        State->ShutdownTimedOut = Shutdown.TimedOut;
        if (Shutdown.TimedOut)
        {
            State->ShutdownResult = Prism::Fault::Code::Timeout;
            const auto CloseAttempt = StartListenerTransmissionClose(IoContext, Client);
            const bool ShutdownRetired = co_await WaitForShutdownCompletionGuarded(
                IoContext, Shutdown.Completion);
            const bool ClientRetired = co_await WaitForListenerTransmissionCloseGuarded(
                IoContext, CloseAttempt, std::chrono::seconds(3));
            if (!ShutdownRetired || !ClientRetired) IoContext.stop();
            co_return;
        }
        State->ShutdownResult = Shutdown.Result
            ? Prism::Fault::Code::Success : Shutdown.Result.error().Code;
        std::array<std::byte, 1> Tail{};
        const auto TailResult = co_await Prism::Testing::TailReadOutcomeGuarded(Client, Tail);
        const auto TailFailure = TailResult.Result.Failure.Code;
        const bool PeerClosed = !TailResult.TimedOut && TailResult.Result.Bytes == 0U &&
            (TailFailure == Prism::Fault::Code::Eof ||
             TailFailure == Prism::Fault::Code::ConnectionReset);
        const auto CloseAttempt = StartListenerTransmissionClose(IoContext, Client);
        const bool ClientRetired = co_await WaitForListenerTransmissionCloseGuarded(
            IoContext, CloseAttempt, std::chrono::seconds(3));
        State->ClientClosed = PeerClosed && ClientRetired;
        if (!ClientRetired) IoContext.stop();
    }

    struct RetainRegistrationState final
    {
        Prism::Runtime::TcpListener *Listener{nullptr};
        std::shared_ptr<Prism::Runtime::SessionControl> Control;
        std::shared_ptr<ByteChannel> ErrorReady;
        std::shared_ptr<ByteChannel> MetricsReady;
        std::atomic<bool> ErrorSawLiveRegistration{false};
        std::atomic<bool> MetricsSawLiveRegistration{false};
        Prism::Fault::Failure ReportedFailure{};
        bool ErrorObserved{false};
        bool MetricsObserved{false};
    };

    struct RetainRegistrationAcceptor final : Prism::Contract::StreamFactory
    {
        explicit RetainRegistrationAcceptor(std::shared_ptr<RetainRegistrationState> StateValue)
            : State(std::move(StateValue))
        {
        }

        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override
        {
            (void)Input;
            const Prism::Fault::Failure Failure{
                Prism::Fault::Code::AuthFailed};
            const auto Closed = State->Control->CloseOnce();
            EXPECT_TRUE(Closed);
            if (!Closed) co_return std::unexpected(Closed.error());
            State->Control->ReportError(Failure);
            co_return std::unexpected(Failure);
        }

        auto Name() const -> std::string_view override { return "RegistrationRetention"; }

        std::shared_ptr<RetainRegistrationState> State;
    };

    struct RejectingSessionFactory final
    {
        std::shared_ptr<RetainRegistrationState> State;

        auto operator()(Prism::Runtime::SessionAdmission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            Prism::Runtime::SessionOptions Options;
            Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>();
            Options.Services->AcceptProtocol =
                std::make_shared<RetainRegistrationAcceptor>(State);
            auto SessionOwner = std::make_shared<Prism::Runtime::Session>(std::move(Options));
            State->Control = SessionOwner->Control();
            return SessionOwner;
        }
    };

    struct RetainRegistrationErrorHook final
    {
        std::shared_ptr<RetainRegistrationState> State;

        auto operator()(std::uint64_t, Prism::Fault::Failure Failure) const -> void
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

        auto operator()(std::uint64_t, const Prism::Runtime::SessionMetrics &Metrics) const -> void
        {
            if (Metrics.CloseCalls == 0U) return;
            State->MetricsSawLiveRegistration.store(
                State->Listener->Registry().Size() == 1U, std::memory_order_release);
            (void)State->MetricsReady->try_send(boost::system::error_code{});
        }
    };

    struct RetainRegistrationRequest final
    {
        Net::io_context *Ioc;
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<RetainRegistrationState> State;
    };

    auto RunRetainRegistration(RetainRegistrationRequest Request) -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Listener->Start(
                      Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
                  Prism::Fault::Code::Success);
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({
            *Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        EXPECT_TRUE(Dialed);
        if (!Dialed)
        {
            Request.Listener->Stop();
            co_return;
        }
        auto Client = std::move(*Dialed);
        const auto Greeting = std::array{
            std::byte{0x05}, std::byte{0x01}, std::byte{0x00}};
        const auto Written = co_await Client->WriteExact(Greeting);
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, Greeting.size());
        Request.State->ErrorObserved = co_await WaitForSignalOrTimeout(
            Request.State->ErrorReady, *Request.Ioc);
        Request.State->MetricsObserved = co_await WaitForSignalOrTimeout(
            Request.State->MetricsReady, *Request.Ioc);
        const auto Shutdown = co_await Request.Listener->Shutdown();
        EXPECT_TRUE(Shutdown);
        (void)Client->Close();
    }

}

TEST(TcpListener, ShutdownDrainsActiveSessionBeforeConnectionRetirement)
    {
        Net::io_context Ioc;
        auto State = std::make_shared<ActiveSessionShutdownState>(Ioc.get_executor());
        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{71};
        ProcessOptions.Generation = Prism::GenerationId{81};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 1;
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory = ActiveSessionShutdownFactory{State, &ProcessValue.Workers()};
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(Ioc, RunActiveSessionShutdownProbe(Ioc, Listener, State));
        EXPECT_EQ(State->StartResult, Prism::Fault::Code::Success);
        EXPECT_TRUE(State->PayloadObserved.load(std::memory_order_acquire));
        EXPECT_EQ(State->ShutdownResult, Prism::Fault::Code::Success);
        EXPECT_FALSE(State->ShutdownTimedOut);
        EXPECT_TRUE(State->ClientClosed);
    }

TEST(TcpListenerLifecycle, RetainsRegistrationUntilFinalHookDelivery)
    {
        Net::io_context Ioc;
        auto ErrorReady = MakeReleaseChannel(Ioc.get_executor());
        auto MetricsReady = MakeReleaseChannel(Ioc.get_executor());
        auto State = std::make_shared<RetainRegistrationState>();
        State->ErrorReady = ErrorReady;
        State->MetricsReady = MetricsReady;
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            Prism::Runtime::TcpListener::Options{
                .Executor = Ioc.get_executor(),
                .Factory = RejectingSessionFactory{State},
                .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                    Prism::GenerationId{1})});
        State->Listener = Listener.get();
        Listener->Registry().SetErrorHook(RetainRegistrationErrorHook{State});
        Listener->Registry().SetMetricsHook(RetainRegistrationMetricsHook{State});

        RunCoro(Ioc, RunRetainRegistration(RetainRegistrationRequest{
            &Ioc, Ioc.get_executor(), Listener, State}));

        EXPECT_TRUE(State->ErrorObserved);
        EXPECT_TRUE(State->MetricsObserved);
        EXPECT_TRUE(State->ErrorSawLiveRegistration.load(std::memory_order_acquire));
        EXPECT_TRUE(State->MetricsSawLiveRegistration.load(std::memory_order_acquire));
        EXPECT_EQ(State->ReportedFailure.Code, Prism::Fault::Code::AuthFailed);
        EXPECT_FALSE(State->ReportedFailure.Native);
        EXPECT_EQ(Listener->Registry().Size(), 0U);
    }
