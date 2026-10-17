/**
 * @file ListenerMuxShutdownTest.cpp
 * @brief 验证活动 mux root 在 listener 连接退休前完成协议关闭。
 */
#include "ListenerTestSupport.hpp"

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Contract/Ingress/MuxSession.hpp>
#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>

#include <chrono>
#include <exception>
#include <optional>
#include <variant>

namespace
{
    using Signal = ListenerTestEvents;
    using MuxCloseState = std::shared_ptr<struct MuxShutdownState>;

    class ProbeMuxSession;

    struct MuxShutdownState final
    {
        explicit MuxShutdownState(Net::any_io_executor ExecutorValue)
            : Executor(std::move(ExecutorValue)),
              GenerationUseState(std::make_shared<Preview::Foundation::GenerationUseState>()),
              PayloadConsumed(Executor, 1), StopRequested(Executor, 1), RunFinished(Executor, 1),
              PeerClosed(Executor, 1)
        {
        }

        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState;
        Signal PayloadConsumed;
        Signal StopRequested;
        Signal RunFinished;
        Signal PeerClosed;
        std::weak_ptr<ProbeMuxSession> Root;
        std::weak_ptr<Preview::Runtime::Session> RuntimeSession;
        std::atomic<int> Stage{0};
        std::atomic<bool> PayloadObserved{false};
        std::atomic<bool> RunReturned{false};
        std::atomic<bool> RawOpenAtMuxClose{false};
        std::atomic<bool> MuxCloseObserved{false};
        std::atomic<int> MuxCloseCount{0};
        std::atomic<bool> PayloadWaitTimedOut{false};
        std::atomic<bool> ShutdownWaitTimedOut{false};
        std::atomic<bool> WaitForPeerClose{false};
        std::atomic<bool> PeerCloseObserved{false};
        Preview::Fault::Code ShutdownResult{Preview::Fault::Code::GenericError};
        bool ClientClosed{false};
    };

    class ProbeMuxActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        explicit ProbeMuxActivity(MuxCloseState StateValue) : State_(std::move(StateValue)) {}

        auto Seal() noexcept -> void override {}

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return State_->Executor;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return State_->RunReturned.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (!IsRetired())
            {
                boost::system::error_code Error;
                co_await State_->RunFinished.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return std::unexpected(
                        Preview::Fault::FromNative(static_cast<std::error_code>(Error)));
                }
            }
            if (!IsRetired())
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

    private:
        MuxCloseState State_;
    };

    class ProbeMuxSession final : public Preview::Contract::MuxSession
    {
    public:
        ProbeMuxSession(Preview::SharedTransmission RawValue, MuxCloseState StateValue)
            : Raw_(std::move(RawValue)), State_(std::move(StateValue)),
              Activity_(std::make_shared<ProbeMuxActivity>(State_))
        {
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Run(Preview::Contract::MuxRootRequest Request)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            (void)Request;
            State_->Stage.store(2, std::memory_order_release);
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            std::array<std::byte, 1> Payload{};
            const auto Read = co_await Raw_->ReadExact(Payload);
            if (Read.Failure.Failed() || Read.Bytes != Payload.size())
            {
                State_->Stage.store(20, std::memory_order_release);
                FinishRun();
                co_return std::unexpected(
                    Read.Failure.Failed() ? Read.Failure :
                    Preview::Fault::Failure{Preview::Fault::Code::IoError});
            }
            State_->PayloadObserved.store(Payload[0] == std::byte{0x05}, std::memory_order_release);
            State_->Stage.store(3, std::memory_order_release);
            (void)State_->PayloadConsumed.try_send(boost::system::error_code{});
            boost::system::error_code Error;
            co_await State_->StopRequested.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            FinishRun();
            if (Error)
            {
                co_return std::unexpected(
                    Preview::Fault::FromNative(static_cast<std::error_code>(Error)));
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Activity_->IsRetired();
        }

        auto Cancel() noexcept -> void override
        {
            (void)State_->StopRequested.try_send(boost::system::error_code{});
        }

        auto Close() noexcept -> void override
        {
            if (!State_->MuxCloseObserved.exchange(true, std::memory_order_acq_rel))
            {
                State_->Stage.store(4, std::memory_order_release);
                State_->RawOpenAtMuxClose.store(Raw_->IsOpen(), std::memory_order_release);
                State_->MuxCloseCount.fetch_add(1, std::memory_order_relaxed);
            }
            (void)Raw_->Cancel();
            (void)Raw_->Close();
            (void)State_->StopRequested.try_send(boost::system::error_code{});
        }

    private:
        auto FinishRun() noexcept -> void
        {
            if (!State_->RunReturned.exchange(true, std::memory_order_acq_rel))
            {
                (void)State_->RunFinished.try_send(boost::system::error_code{});
            }
        }

        Preview::SharedTransmission Raw_;
        MuxCloseState State_;
        std::shared_ptr<ProbeMuxActivity> Activity_;
    };

    auto AcceptMuxShutdownPlane(
        const std::shared_ptr<MuxShutdownState> &State,
        Preview::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        auto Root = std::make_shared<ProbeMuxSession>(Input.Inbound, State);
        State->Root = Root;
        State->Stage.store(1, std::memory_order_release);
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Preview::Contract::ProtocolType::Socks5;
        Plane.ProtocolAuthenticated = true;
        Plane.Root = Preview::Contract::MuxRootDataPlane{Input.Inbound, std::move(Root)};
        co_return Plane;
    }

    struct MuxShutdownSessionFactory final
    {
        MuxCloseState State;
        Preview::Runtime::WorkerGroup *Workers{nullptr};

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            auto Options = MakeListenerWorkerSessionOptions(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.SourceIp = std::move(Admission.SourceIp);
            Options.Services->Generation = Admission.Generation;
            Options.Services->GenerationUseState = State->GenerationUseState;
            Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
                [State = State](Preview::Contract::StreamAcceptInput Input)
                {
                    return AcceptMuxShutdownPlane(State, std::move(Input));
                });
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    struct ListenerShutdownOutcome final
    {
        bool TimedOut{false};
        std::expected<void, Preview::Fault::Failure> Result;
        std::shared_ptr<ListenerOperationCompletion> Completion;
    };

    /** @brief 在活动探针之外启动 listener 关闭，再以独立 deadline 有界观察。 */
    auto ShutdownListenerGuarded(
        Net::io_context &IoContext,
        const std::shared_ptr<Preview::Runtime::TcpListener> &Listener)
        -> Net::awaitable<ListenerShutdownOutcome>
    {
        const auto Completion = StartListenerOperation(IoContext, Listener->Shutdown());
        const auto Outcome = co_await WaitForListenerOperationGuarded(
            IoContext, Completion, std::chrono::seconds(3));
        if (Outcome.TimedOut) Listener->Stop();
        co_return ListenerShutdownOutcome{
            Outcome.TimedOut, std::move(Outcome.Result), Completion};
    }

    auto FinishListenerShutdownAfterProbeFailure(
        Net::io_context &IoContext,
        const std::shared_ptr<Preview::Runtime::TcpListener> &Listener,
        const Preview::SharedTransmission &Client = {})
        -> Net::awaitable<ListenerShutdownOutcome>
    {
        ListenerTransmissionCloseAttempt CloseAttempt;
        if (Client) CloseAttempt = StartListenerTransmissionClose(IoContext, Client);
        const auto Shutdown = co_await ShutdownListenerGuarded(IoContext, Listener);
        auto ShutdownRetired = !Shutdown.TimedOut && static_cast<bool>(Shutdown.Result);
        if (Shutdown.TimedOut)
        {
            const auto Wait = co_await WaitForListenerOperationGuarded(
                IoContext, Shutdown.Completion, std::chrono::seconds(3));
            ShutdownRetired = !Wait.TimedOut && static_cast<bool>(Wait.Result);
        }
        const bool ClientRetired = !Client ||
            co_await WaitForListenerTransmissionCloseGuarded(
                IoContext, CloseAttempt, std::chrono::seconds(3));
        if (!ShutdownRetired || !ClientRetired) IoContext.stop();
        co_return Shutdown;
    }

    auto RunMuxShutdownProbe(
        Net::io_context &IoContext,
        const std::shared_ptr<Preview::Runtime::TcpListener> &Listener,
        const std::shared_ptr<MuxShutdownState> &State) -> Net::awaitable<void>
    {
        const auto Started = co_await Listener->Start(Tcp::endpoint(Tcp::v4(), 0));
        if (Started != Preview::Fault::Code::Success)
        {
            State->ShutdownResult = Started;
            co_return;
        }
        State->Stage.store(10, std::memory_order_release);
        Preview::Network::Dialer::Dialer Dialer(IoContext.get_executor());
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer ConnectWatchdog(IoContext);
        ConnectWatchdog.expires_after(std::chrono::seconds(3));
        const auto ConnectWait = co_await (
            Dialer.Connect(
                {*Preview::Network::ParseHost("127.0.0.1"), Listener->LocalEndpoint().port()}) ||
            ExpireListenerTestWatchdog(ConnectWatchdog));
        if (ConnectWait.index() != 0U)
        {
            State->ShutdownResult = Preview::Fault::Code::Timeout;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(IoContext, Listener);
            State->ShutdownWaitTimedOut.store(Cleanup.TimedOut, std::memory_order_release);
            co_return;
        }
        auto Dialed = std::get<0>(ConnectWait);
        if (!Dialed)
        {
            State->ShutdownResult = Dialed.error().Code;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(IoContext, Listener);
            State->ShutdownWaitTimedOut.store(Cleanup.TimedOut, std::memory_order_release);
            co_return;
        }
        auto Client = std::move(*Dialed);
        State->Stage.store(11, std::memory_order_release);
        const auto Greeting = Socks5Greeting();
        Net::steady_timer WriteWatchdog(IoContext);
        WriteWatchdog.expires_after(std::chrono::seconds(3));
        const auto WriteWait = co_await (
            Client->WriteSome(std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size())) ||
            ExpireListenerTestWatchdog(WriteWatchdog));
        if (WriteWait.index() != 0U)
        {
            State->ShutdownResult = Preview::Fault::Code::Timeout;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(
                IoContext, Listener, Client);
            State->ShutdownWaitTimedOut.store(Cleanup.TimedOut, std::memory_order_release);
            co_return;
        }
        const auto Written = std::get<0>(WriteWait);
        if (Written.Failure.Failed() || Written.Bytes != Greeting.size())
        {
            State->ShutdownResult = Written.Failure.Failed()
                ? Written.Failure.Code : Preview::Fault::Code::IoError;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(
                IoContext, Listener, Client);
            State->ShutdownWaitTimedOut.store(Cleanup.TimedOut, std::memory_order_release);
            co_return;
        }
        State->Stage.store(12, std::memory_order_release);
        Net::steady_timer PayloadWatchdog(IoContext);
        PayloadWatchdog.expires_after(std::chrono::seconds(3));
        const auto PayloadWait = co_await (
            ReceiveListenerTestEvent(State->PayloadConsumed) ||
            ExpireListenerTestWatchdog(PayloadWatchdog));
        if (PayloadWait.index() != 0U || !std::get<0>(PayloadWait))
        {
            State->PayloadWaitTimedOut.store(true, std::memory_order_release);
            State->Stage.store(21, std::memory_order_release);
            if (const auto Root = State->Root.lock()) Root->Close();
            State->ShutdownResult = Preview::Fault::Code::Timeout;
            const auto Cleanup = co_await FinishListenerShutdownAfterProbeFailure(
                IoContext, Listener, Client);
            State->ShutdownWaitTimedOut.store(Cleanup.TimedOut, std::memory_order_release);
            co_return;
        }
        State->Stage.store(13, std::memory_order_release);
        const auto Shutdown = co_await ShutdownListenerGuarded(IoContext, Listener);
        State->ShutdownWaitTimedOut.store(Shutdown.TimedOut, std::memory_order_release);
        if (Shutdown.TimedOut)
        {
            if (const auto Root = State->Root.lock()) Root->Close();
            const auto CloseAttempt = StartListenerTransmissionClose(IoContext, Client);
            const auto ShutdownWait = co_await WaitForListenerOperationGuarded(
                IoContext, Shutdown.Completion, std::chrono::seconds(3));
            const bool ClientRetired = co_await WaitForListenerTransmissionCloseGuarded(
                IoContext, CloseAttempt, std::chrono::seconds(3));
            if (ShutdownWait.TimedOut || !ShutdownWait.Result || !ClientRetired)
                IoContext.stop();
            co_return;
        }
        State->ShutdownResult = Shutdown.Result
            ? Preview::Fault::Code::Success : Shutdown.Result.error().Code;
        State->Stage.store(14, std::memory_order_release);
        std::array<std::byte, 1> Tail{};
        const auto TailResult = co_await Preview::Testing::TailReadOutcomeGuarded(Client, Tail);
        const auto TailFailure = TailResult.Result.Failure.Code;
        const bool PeerClosed = !TailResult.TimedOut && TailResult.Result.Bytes == 0U &&
            (TailFailure == Preview::Fault::Code::Eof ||
             TailFailure == Preview::Fault::Code::ConnectionReset);
        const auto CloseAttempt = StartListenerTransmissionClose(IoContext, Client);
        const bool ClientRetired = co_await WaitForListenerTransmissionCloseGuarded(
            IoContext, CloseAttempt, std::chrono::seconds(3));
        State->ClientClosed = PeerClosed && ClientRetired;
        if (!ClientRetired) IoContext.stop();
    }
}

TEST(TcpListener, MuxOwnerClosesRootBeforeListenerRetiresConnection)
{
    Net::io_context Ioc;
    auto State = std::make_shared<MuxShutdownState>(Ioc.get_executor());
    Preview::Runtime::Process::Options ProcessOptions;
    ProcessOptions.Id = Preview::ProcessId{91};
    ProcessOptions.Generation = Preview::GenerationId{101};
    ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
        ProcessOptions.Generation);
    ProcessOptions.WorkerCount = 1;
    Preview::Runtime::Process ProcessValue(ProcessOptions);
    WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

    Preview::Runtime::TcpListener::Options ListenerOptions;
    ListenerOptions.Executor = Ioc.get_executor();
    ListenerOptions.Workers = &ProcessValue.Workers();
    ListenerOptions.Publication = ProcessOptions.Publication;
    ListenerOptions.Factory = MuxShutdownSessionFactory{State, &ProcessValue.Workers()};
    auto Listener = std::make_shared<Preview::Runtime::TcpListener>(std::move(ListenerOptions));

    RunCoro(Ioc, RunMuxShutdownProbe(Ioc, Listener, State));
        EXPECT_FALSE(State->PayloadWaitTimedOut.load(std::memory_order_acquire))
            << "mux probe stage=" << State->Stage.load(std::memory_order_acquire);
        EXPECT_FALSE(State->ShutdownWaitTimedOut.load(std::memory_order_acquire))
            << "shutdown probe stage=" << State->Stage.load(std::memory_order_acquire);
    EXPECT_TRUE(State->PayloadObserved.load(std::memory_order_acquire));
    EXPECT_TRUE(State->MuxCloseObserved.load(std::memory_order_acquire));
    EXPECT_TRUE(State->RawOpenAtMuxClose.load(std::memory_order_acquire));
    EXPECT_EQ(State->MuxCloseCount.load(std::memory_order_acquire), 1);
    EXPECT_TRUE(State->RunReturned.load(std::memory_order_acquire));
    EXPECT_EQ(State->ShutdownResult, Preview::Fault::Code::Success);
    EXPECT_TRUE(State->ClientClosed);
    EXPECT_EQ(State->Stage.load(std::memory_order_acquire), 14);
}
