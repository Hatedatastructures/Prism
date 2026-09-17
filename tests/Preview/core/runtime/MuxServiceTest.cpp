/**
 * @file MuxServiceTest.cpp
 * @brief Preview owned MuxService lifecycle and child-stream contract tests.
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <variant>

#include <Preview/Protocols/Mux/Client.hpp>
#include <Preview/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Composition/MuxService.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::Fault::Code;
    using Preview::MemoryStream;
    using AsyncSignal = Net::experimental::channel<void(boost::system::error_code)>;

    inline constexpr std::chrono::seconds OperationTimeout{2};

    auto WaitForSignal(const std::shared_ptr<AsyncSignal> &SignalValue,
                       Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Timer(std::move(Executor));
        Timer.expires_after(OperationTimeout);
        const auto Result = co_await (
            SignalValue->async_receive(Net::use_awaitable) || Timer.async_wait(Net::use_awaitable));
        co_return Result.index() == 0;
    }

    auto DrainControlWithTimeout(
        const std::shared_ptr<Preview::Runtime::SessionControl> &Control,
        Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Timer(std::move(Executor));
        Timer.expires_after(OperationTimeout);
        const auto Result = co_await (Control->Drain() || Timer.async_wait(Net::use_awaitable));
        co_return Result.index() == 0;
    }

    template <typename Client>
    auto OpenStreamWithTimeout(const std::shared_ptr<Client> &ClientValue,
                               Net::any_io_executor Executor) -> Net::awaitable<Preview::SharedTransmission>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Timer(std::move(Executor));
        Timer.expires_after(OperationTimeout);
        const auto Result = co_await (
            ClientValue->OpenStream() || Timer.async_wait(Net::use_awaitable));
        if (Result.index() != 0)
        {
            co_return nullptr;
        }
        co_return std::get<0>(Result);
    }

    auto WriteByteWithTimeout(Preview::SharedTransmission Stream, std::byte Value,
                              Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        if (!Stream)
        {
            co_return false;
        }
        const std::array<std::byte, 1> Data{Value};
        std::error_code Error;
        Net::steady_timer Timer(std::move(Executor));
        Timer.expires_after(OperationTimeout);
        const auto Result = co_await (
            Stream->async_write_some(std::span<const std::byte>(Data), Error) ||
            Timer.async_wait(Net::use_awaitable));
        co_return Result.index() == 0 && std::get<0>(Result) == Data.size() && !Error;
    }

    auto ReadByteWithTimeout(Preview::SharedTransmission Stream,
                             Net::any_io_executor Executor) -> Net::awaitable<std::optional<std::byte>>
    {
        using Net::experimental::awaitable_operators::operator||;
        if (!Stream)
        {
            co_return std::nullopt;
        }
        std::array<std::byte, 1> Data{};
        std::error_code Error;
        Net::steady_timer Timer(std::move(Executor));
        Timer.expires_after(OperationTimeout);
        const auto Result = co_await (
            Stream->async_read_some(std::span<std::byte>(Data), Error) ||
            Timer.async_wait(Net::use_awaitable));
        if (Result.index() != 0 || Error || std::get<0>(Result) != Data.size())
        {
            co_return std::nullopt;
        }
        co_return Data[0];
    }

    template <typename Client>
    auto OpenTaggedStreamWithTimeout(const std::shared_ptr<Client> &ClientValue, std::byte Marker,
                                     Net::any_io_executor Executor)
        -> Net::awaitable<Preview::SharedTransmission>
    {
        auto Stream = co_await OpenStreamWithTimeout(ClientValue, Executor);
        if (!Stream || !(co_await WriteByteWithTimeout(Stream, Marker, Executor)))
        {
            co_return nullptr;
        }
        co_return Stream;
    }

    template <typename Client>
    auto CloseClientSessionWithTimeout(const std::shared_ptr<Client> &ClientValue,
                                       Net::any_io_executor Executor) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto SessionValue = ClientValue->Session();
        if (!SessionValue)
        {
            co_return true;
        }
        Net::steady_timer Timer(std::move(Executor));
        Timer.expires_after(OperationTimeout);
        const auto Result = co_await (
            SessionValue->Close() || Timer.async_wait(Net::use_awaitable));
        co_return Result.index() == 0;
    }

    auto RunMuxServerRoot(
        std::shared_ptr<Preview::Composition::MuxService> Service,
        std::shared_ptr<Preview::Runtime::SessionControl> Control,
        Preview::SharedTransmission ServerTransport) -> Net::awaitable<Code>
    {
        Preview::Middleware::Context Context;
        Context.Control = std::move(Control);
        co_return co_await Service->Run(std::move(ServerTransport), Context);
    }

    struct RootCompletion final : std::enable_shared_from_this<RootCompletion>
    {
        explicit RootCompletion(Net::any_io_executor Executor)
            : SignalValue(std::make_shared<AsyncSignal>(std::move(Executor), 1))
        {
        }

        auto Start(std::shared_ptr<Preview::Composition::MuxService> Service,
                   std::shared_ptr<Preview::Runtime::SessionControl> Control,
                   Preview::SharedTransmission ServerTransport) -> void
        {
            const auto Self = shared_from_this();
            const auto CompletionControl = Control;
            Net::co_spawn(
                SignalValue->get_executor(),
                RunMuxServerRoot(std::move(Service), std::move(Control), std::move(ServerTransport)),
                [Self, CompletionControl](std::exception_ptr Error, Code Value)
                {
                    Self->ActiveTasksAtCompletion = CompletionControl
                                                        ? CompletionControl->Metrics().Active
                                                        : 0;
                    Self->DrainBlockedAtCompletion = CompletionControl
                                                         ? CompletionControl->IsDrainBlocked()
                                                         : false;
                    Self->Completed = true;
                    Self->Failed = static_cast<bool>(Error);
                    Self->Result = Value;
                    (void)Self->SignalValue->try_send(boost::system::error_code{});
                });
        }

        std::shared_ptr<AsyncSignal> SignalValue;
        Code Result{Code::IoError};
        bool Failed{false};
        bool Completed{false};
        std::size_t ActiveTasksAtCompletion{0};
        bool DrainBlockedAtCompletion{false};
    };

    struct CancelIsolationResult final
    {
        bool InitialRootAStreamHandled{false};
        bool InitialRootBStreamHandled{false};
        bool RootACompleted{false};
        bool RootADrained{false};
        bool RootBCompleted{false};
        bool RootBDrained{false};
        bool RootAThrew{false};
        bool RootBThrew{false};
        bool ClientSessionsClosed{false};
        Code RootAResult{Code::IoError};
        Code RootBResult{Code::IoError};
        std::size_t SiblingStreamsHandled{0};
    };

    struct MarkerHandler final
    {
        std::shared_ptr<AsyncSignal> RootAEvents;
        std::shared_ptr<AsyncSignal> RootBEvents;
        Net::any_io_executor Executor;

        auto operator()(Preview::SharedTransmission Stream,
                        const Preview::Lifecycle::TaskIdentity &) const -> Net::awaitable<Code>
        {
            if (!Stream)
            {
                co_return Code::IoError;
            }
            const auto Marker = co_await ReadByteWithTimeout(Stream, Executor);
            if (!Marker)
            {
                co_return Code::IoError;
            }
            const auto IsRootA = *Marker == std::byte{0xA1};
            const auto IsRootB = *Marker == std::byte{0xB0} ||
                                 *Marker == std::byte{0xB1} ||
                                 *Marker == std::byte{0xB2};
            const auto Events = IsRootA ? RootAEvents : (IsRootB ? RootBEvents : nullptr);
            if (!Events)
            {
                co_return Code::InvalidArgument;
            }
            co_await Events->async_send(boost::system::error_code{}, Net::use_awaitable);
            co_return Code::Success;
        }
    };

    auto RunCancelIsolationCase(Net::io_context &Io) -> Net::awaitable<CancelIsolationResult>
    {
        auto [ServerRawA, ClientRawA] = Preview::MakeMemoryPair(Io.get_executor());
        auto [ServerRawB, ClientRawB] = Preview::MakeMemoryPair(Io.get_executor());
        auto Service = std::make_shared<Preview::Composition::MuxService>(
            Preview::Composition::MuxServiceOptions{.Mode = Preview::Composition::MuxMode::Smux});
        auto HandlerEventsA = std::make_shared<AsyncSignal>(Io.get_executor(), 8);
        auto HandlerEventsB = std::make_shared<AsyncSignal>(Io.get_executor(), 8);
        Service->SetStreamHandler(MarkerHandler{HandlerEventsA, HandlerEventsB, Io.get_executor()});

        auto ControlA = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto ControlB = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto RootA = std::make_shared<RootCompletion>(Io.get_executor());
        auto RootB = std::make_shared<RootCompletion>(Io.get_executor());
        RootA->Start(Service, ControlA, std::make_shared<MemoryStream>(std::move(ServerRawA)));
        RootB->Start(Service, ControlB, std::make_shared<MemoryStream>(std::move(ServerRawB)));

        auto ClientA = std::make_shared<Preview::Mux::Smux::Client<>>();
        auto ClientB = std::make_shared<Preview::Mux::Smux::Client<>>();
        const auto ConnectedA = ClientA->Connect(
            std::make_shared<MemoryStream>(std::move(ClientRawA)));
        const auto ConnectedB = ClientB->Connect(
            std::make_shared<MemoryStream>(std::move(ClientRawB)));
        CancelIsolationResult Result;
        // 保持已打开子流存活，直到所属会话关闭完成。
        std::array<Preview::SharedTransmission, 4> OpenStreams{};
        std::size_t OpenStreamCount = 0;

        if (ConnectedA)
        {
            auto Stream = co_await OpenTaggedStreamWithTimeout(
                ClientA, std::byte{0xA1}, Io.get_executor());
            if (Stream)
            {
                OpenStreams[OpenStreamCount++] = std::move(Stream);
                Result.InitialRootAStreamHandled = co_await WaitForSignal(
                    HandlerEventsA, Io.get_executor());
                // 处理器事件先于受 Control 追踪的任务完成投递。
                co_await Net::post(Io.get_executor(), Net::use_awaitable);
            }
        }
        if (ConnectedB)
        {
            auto Stream = co_await OpenTaggedStreamWithTimeout(
                ClientB, std::byte{0xB0}, Io.get_executor());
            if (Stream)
            {
                OpenStreams[OpenStreamCount++] = std::move(Stream);
                Result.InitialRootBStreamHandled = co_await WaitForSignal(
                    HandlerEventsB, Io.get_executor());
                // 让当前流处理器返回后再推进下一条线上的流。
                co_await Net::post(Io.get_executor(), Net::use_awaitable);
            }
        }

        ControlA->Cancel();
        Result.RootACompleted = co_await WaitForSignal(RootA->SignalValue, Io.get_executor());
        Result.RootADrained = co_await DrainControlWithTimeout(ControlA, Io.get_executor());
        if (Result.RootACompleted)
        {
            Result.RootAThrew = RootA->Failed;
            Result.RootAResult = RootA->Result;
        }
        if (ConnectedB)
        {
            for (std::size_t Index = 0; Index < 2; ++Index)
            {
                const auto Marker = Index == 0 ? std::byte{0xB1} : std::byte{0xB2};
                auto Stream = co_await OpenTaggedStreamWithTimeout(
                    ClientB, Marker, Io.get_executor());
                if (!Stream)
                {
                    break;
                }
                OpenStreams[OpenStreamCount++] = std::move(Stream);
                if (!(co_await WaitForSignal(HandlerEventsB, Io.get_executor())))
                {
                    break;
                }
                ++Result.SiblingStreamsHandled;
                // 确认当前流处理器收尾后再打开下一条流。
                co_await Net::post(Io.get_executor(), Net::use_awaitable);
            }
        }

        const auto ClientAClosed = co_await CloseClientSessionWithTimeout(ClientA, Io.get_executor());
        const auto ClientBClosed = co_await CloseClientSessionWithTimeout(ClientB, Io.get_executor());
        Result.ClientSessionsClosed = ClientAClosed && ClientBClosed;
        Result.RootBCompleted = co_await WaitForSignal(RootB->SignalValue, Io.get_executor());
        Result.RootBDrained = co_await DrainControlWithTimeout(ControlB, Io.get_executor());
        if (Result.RootBCompleted)
        {
            Result.RootBThrew = RootB->Failed;
            Result.RootBResult = RootB->Result;
        }
        if (!Result.RootACompleted)
        {
            Result.RootACompleted = co_await WaitForSignal(RootA->SignalValue, Io.get_executor());
            if (Result.RootACompleted)
            {
                Result.RootAThrew = RootA->Failed;
                Result.RootAResult = RootA->Result;
            }
        }
        // 排空根完成回调后再让 RunCoro 停止 io_context。
        co_await Net::post(Io.get_executor(), Net::use_awaitable);
        co_return Result;
    }

    auto RunCountingHandler(std::shared_ptr<std::atomic<std::size_t>> HandlerInvocations,
                            Preview::SharedTransmission Stream) -> Net::awaitable<Code>
    {
        HandlerInvocations->fetch_add(1, std::memory_order_relaxed);
        co_return Stream ? Code::Success : Code::IoError;
    }

    struct StopDrainHandler final
    {
        std::shared_ptr<AsyncSignal> Started;
        std::shared_ptr<std::atomic<bool>> Finished;
        std::shared_ptr<std::atomic<std::size_t>> Invocations;

        auto operator()(Preview::SharedTransmission Stream,
                        const Preview::Lifecycle::TaskIdentity &) const -> Net::awaitable<Code>
        {
            Invocations->fetch_add(1, std::memory_order_relaxed);
            if (!Stream)
            {
                Finished->store(true, std::memory_order_release);
                co_return Code::IoError;
            }
            std::array<std::byte, 1> Buffer{};
            std::error_code Error;
            const auto MarkerBytes = co_await Stream->async_read_some(
                std::span<std::byte>(Buffer), Error);
            if (Error || MarkerBytes != Buffer.size())
            {
                Finished->store(true, std::memory_order_release);
                co_return Code::IoError;
            }
            co_await Started->async_send(boost::system::error_code{}, Net::use_awaitable);
            Error.clear();
            const auto TailBytes = co_await Stream->async_read_some(
                std::span<std::byte>(Buffer), Error);
            Finished->store(true, std::memory_order_release);
            co_return Error || TailBytes == 0 ? Code::Canceled : Code::Success;
        }
    };

    auto SignalTaskStart(
        const std::shared_ptr<Preview::Runtime::SessionControl> &Control,
        const std::shared_ptr<AsyncSignal> &Signal) -> void
    {
        Control->SetMetricsHook(
            [Signal](const Preview::Runtime::SessionMetrics &Metrics)
            {
                if (Metrics.Started != 0)
                {
                    (void)Signal->try_send(boost::system::error_code{});
                }
            });
    }

    struct ServiceStopResult final
    {
        bool ClientAConnected{false};
        bool ClientBConnected{false};
        bool ChildStarted{false};
        bool IdleRootWaiting{false};
        bool RootACompletedOnStop{false};
        bool RootBCompletedOnStop{false};
        bool RootAChildFinishedAtCompletion{false};
        bool RootADrainedOnStop{false};
        bool RootBDrainedOnStop{false};
        bool RootAThrew{false};
        bool RootBThrew{false};
        Code RootAResult{Code::IoError};
        Code RootBResult{Code::IoError};
        std::size_t RootAActiveTasksAtCompletion{0};
        std::size_t RootBActiveTasksAtCompletion{0};
        bool RootADrainBlockedAtCompletion{false};
        bool RootBDrainBlockedAtCompletion{false};
        std::size_t HandlerInvocations{0};
    };

    auto RunServiceStopCase(Net::io_context &Io) -> Net::awaitable<ServiceStopResult>
    {
        auto [ServerRawA, ClientRawA] = Preview::MakeMemoryPair(Io.get_executor());
        auto [ServerRawB, ClientRawB] = Preview::MakeMemoryPair(Io.get_executor());
        auto ServerTransportA = std::make_shared<MemoryStream>(std::move(ServerRawA));
        auto ServerTransportB = std::make_shared<MemoryStream>(std::move(ServerRawB));
        auto RootWaiting = std::make_shared<AsyncSignal>(Io.get_executor(), 4);
        auto Service = std::make_shared<Preview::Composition::MuxService>(
            Preview::Composition::MuxServiceOptions{
                .Mode = Preview::Composition::MuxMode::Smux,
                .RootWaitingFn = [RootWaiting]
                {
                    (void)RootWaiting->try_send(boost::system::error_code{});
                }});
        auto HandlerStarted = std::make_shared<AsyncSignal>(Io.get_executor(), 1);
        auto HandlerFinished = std::make_shared<std::atomic<bool>>(false);
        auto HandlerInvocations = std::make_shared<std::atomic<std::size_t>>(0);
        Service->SetStreamHandler(
            StopDrainHandler{HandlerStarted, HandlerFinished, HandlerInvocations});

        auto ControlA = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto ControlB = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto ReadyB = std::make_shared<AsyncSignal>(Io.get_executor(), 1);
        SignalTaskStart(ControlB, ReadyB);
        auto RootA = std::make_shared<RootCompletion>(Io.get_executor());
        auto RootB = std::make_shared<RootCompletion>(Io.get_executor());
        RootA->Start(Service, ControlA, ServerTransportA);
        RootB->Start(Service, ControlB, ServerTransportB);

        auto ClientA = std::make_shared<Preview::Mux::Smux::Client<>>();
        auto ClientB = std::make_shared<Preview::Mux::Smux::Client<>>();
        ServiceStopResult Result;
        Result.ClientAConnected = ClientA->Connect(
            std::make_shared<MemoryStream>(std::move(ClientRawA)));
        Result.ClientBConnected = ClientB->Connect(
            std::make_shared<MemoryStream>(std::move(ClientRawB)));
        const auto RootAWaiting = co_await WaitForSignal(RootWaiting, Io.get_executor());
        const auto RootBWaiting = co_await WaitForSignal(RootWaiting, Io.get_executor());
        Result.IdleRootWaiting = RootAWaiting && RootBWaiting && !RootA->Completed &&
                                 !RootB->Completed;
        Preview::SharedTransmission Child;
        if (Result.ClientAConnected)
        {
            Child = co_await OpenTaggedStreamWithTimeout(
                ClientA, std::byte{0xA1}, Io.get_executor());
            if (Child)
            {
                Result.ChildStarted = co_await WaitForSignal(HandlerStarted, Io.get_executor());
            }
        }

        const auto IdleRootStarted = co_await WaitForSignal(ReadyB, Io.get_executor());
        co_await Net::post(Io.get_executor(), Net::use_awaitable);
        Result.IdleRootWaiting = Result.IdleRootWaiting && IdleRootStarted &&
                                 HandlerInvocations->load(std::memory_order_relaxed) == 1;
        Service->Stop();
        Service->Stop();
        Result.RootACompletedOnStop = co_await WaitForSignal(
            RootA->SignalValue, Io.get_executor());
        Result.RootBCompletedOnStop = co_await WaitForSignal(
            RootB->SignalValue, Io.get_executor());
        Result.RootAChildFinishedAtCompletion = HandlerFinished->load(std::memory_order_acquire);
        if (Result.RootACompletedOnStop)
        {
            Result.RootAThrew = RootA->Failed;
            Result.RootAResult = RootA->Result;
            Result.RootAActiveTasksAtCompletion = RootA->ActiveTasksAtCompletion;
            Result.RootADrainBlockedAtCompletion = RootA->DrainBlockedAtCompletion;
        }
        if (Result.RootBCompletedOnStop)
        {
            Result.RootBThrew = RootB->Failed;
            Result.RootBResult = RootB->Result;
            Result.RootBActiveTasksAtCompletion = RootB->ActiveTasksAtCompletion;
            Result.RootBDrainBlockedAtCompletion = RootB->DrainBlockedAtCompletion;
        }
        Result.RootADrainedOnStop = co_await DrainControlWithTimeout(ControlA, Io.get_executor());
        Result.RootBDrainedOnStop = co_await DrainControlWithTimeout(ControlB, Io.get_executor());

        if (!Result.RootACompletedOnStop)
        {
            ServerTransportA->Close();
            (void)co_await WaitForSignal(RootA->SignalValue, Io.get_executor());
        }
        if (!Result.RootBCompletedOnStop)
        {
            ServerTransportB->Close();
            (void)co_await WaitForSignal(RootB->SignalValue, Io.get_executor());
        }
        (void)co_await CloseClientSessionWithTimeout(ClientA, Io.get_executor());
        (void)co_await CloseClientSessionWithTimeout(ClientB, Io.get_executor());
        co_await Net::post(Io.get_executor(), Net::use_awaitable);
        Result.HandlerInvocations = HandlerInvocations->load(std::memory_order_relaxed);
        co_return Result;
    }

    struct NoControlStopResult final
    {
        bool RootWaiting{false};
        bool ClientConnected{false};
        bool ChildStarted{false};
        bool RootCompletedOnStop{false};
        bool ChildFinishedAtCompletion{false};
        bool RootThrew{false};
        Code RootResult{Code::IoError};
    };

    auto RunNoControlStopCase(Net::io_context &Io) -> Net::awaitable<NoControlStopResult>
    {
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerRaw));
        auto RootWaiting = std::make_shared<AsyncSignal>(Io.get_executor(), 1);
        auto HandlerStarted = std::make_shared<AsyncSignal>(Io.get_executor(), 1);
        auto HandlerFinished = std::make_shared<std::atomic<bool>>(false);
        auto HandlerInvocations = std::make_shared<std::atomic<std::size_t>>(0);
        auto Service = std::make_shared<Preview::Composition::MuxService>(
            Preview::Composition::MuxServiceOptions{
                .Mode = Preview::Composition::MuxMode::Smux,
                .RootWaitingFn = [RootWaiting]
                {
                    (void)RootWaiting->try_send(boost::system::error_code{});
                }});
        Service->SetStreamHandler(
            StopDrainHandler{HandlerStarted, HandlerFinished, HandlerInvocations});

        auto Root = std::make_shared<RootCompletion>(Io.get_executor());
        Root->Start(Service, {}, ServerTransport);
        auto Client = std::make_shared<Preview::Mux::Smux::Client<>>();
        NoControlStopResult Result;
        Result.RootWaiting = co_await WaitForSignal(RootWaiting, Io.get_executor());
        Result.ClientConnected = Client->Connect(
            std::make_shared<MemoryStream>(std::move(ClientRaw)));
        auto Child = co_await OpenTaggedStreamWithTimeout(
            Client, std::byte{0xA1}, Io.get_executor());
        if (Child)
        {
            Result.ChildStarted = co_await WaitForSignal(HandlerStarted, Io.get_executor());
        }
        Service->Stop();
        Result.RootCompletedOnStop = co_await WaitForSignal(
            Root->SignalValue, Io.get_executor());
        Result.ChildFinishedAtCompletion = HandlerFinished->load(std::memory_order_acquire);
        if (Result.RootCompletedOnStop)
        {
            Result.RootThrew = Root->Failed;
            Result.RootResult = Root->Result;
        }
        if (!Result.RootCompletedOnStop)
        {
            ServerTransport->Close();
            (void)co_await WaitForSignal(Root->SignalValue, Io.get_executor());
        }
        (void)co_await CloseClientSessionWithTimeout(Client, Io.get_executor());
        co_await Net::post(Io.get_executor(), Net::use_awaitable);
        co_return Result;
    }

    struct StartRejectedResult final
    {
        bool ServerReady{false};
        bool ClientConnected{false};
        bool CloseAccepted{false};
        bool StreamOpened{false};
        bool RootCompletedBeforeCleanup{false};
        bool RootCompletedAfterCleanup{false};
        bool RootThrew{false};
        bool ServerOpenBeforeCleanup{false};
        bool ClientClosed{false};
        bool ServerClosedAfterCleanup{false};
        bool ControlDrained{false};
        Code RootResult{Code::IoError};
        std::size_t StartedBeforeAttempt{0};
        std::size_t StartedAfterAttempt{0};
        std::size_t HandlerInvocations{0};
        std::size_t ActiveTasksAtCompletion{0};
    };

    auto RunStartRejectedCase(Net::io_context &Io) -> Net::awaitable<StartRejectedResult>
    {
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerRaw));
        auto Service = std::make_shared<Preview::Composition::MuxService>(
            Preview::Composition::MuxServiceOptions{.Mode = Preview::Composition::MuxMode::Smux});
        auto HandlerInvocations = std::make_shared<std::atomic<std::size_t>>(0);
        Service->SetStreamHandler(
            [HandlerInvocations](Preview::SharedTransmission Stream,
                                 const Preview::Lifecycle::TaskIdentity &)
            {
                return RunCountingHandler(HandlerInvocations, std::move(Stream));
            });

        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto Ready = std::make_shared<AsyncSignal>(Io.get_executor(), 1);
        Control->SetMetricsHook(
            [Ready](const Preview::Runtime::SessionMetrics &Metrics)
            {
                if (Metrics.Started >= 1)
                {
                    (void)Ready->try_send(boost::system::error_code{});
                }
            });
        auto Root = std::make_shared<RootCompletion>(Io.get_executor());
        Root->Start(Service, Control, ServerTransport);
        auto Client = std::make_shared<Preview::Mux::Smux::Client<>>();
        StartRejectedResult Result;
        Result.ClientConnected = Client->Connect(
            std::make_shared<MemoryStream>(std::move(ClientRaw)));
        Result.ServerReady = co_await WaitForSignal(Ready, Io.get_executor());
        co_await Net::post(Io.get_executor(), Net::use_awaitable);

        if (Result.ServerReady)
        {
            Result.StartedBeforeAttempt = Control->Metrics().Started;
            Result.CloseAccepted = Control->CloseOnce(std::function<void()>{});
            if (Result.ClientConnected)
            {
                auto Stream = co_await OpenStreamWithTimeout(Client, Io.get_executor());
                Result.StreamOpened = static_cast<bool>(Stream);
                if (Stream)
                {
                    Result.RootCompletedBeforeCleanup = co_await WaitForSignal(
                        Root->SignalValue, Io.get_executor());
                    Result.ServerOpenBeforeCleanup = ServerTransport->IsOpen();
                    Result.StartedAfterAttempt = Control->Metrics().Started;
                    Result.HandlerInvocations =
                        HandlerInvocations->load(std::memory_order_relaxed);
                    if (Result.RootCompletedBeforeCleanup)
                    {
                        Result.RootThrew = Root->Failed;
                        Result.RootResult = Root->Result;
                    }
                }
            }
        }

        Result.ClientClosed = co_await CloseClientSessionWithTimeout(Client, Io.get_executor());
        ServerTransport->Close();
        Result.ServerClosedAfterCleanup = !ServerTransport->IsOpen();
        if (!Result.RootCompletedBeforeCleanup)
        {
            Result.RootCompletedAfterCleanup = co_await WaitForSignal(
                Root->SignalValue, Io.get_executor());
            if (Result.RootCompletedAfterCleanup)
            {
                Result.RootThrew = Root->Failed;
                Result.RootResult = Root->Result;
            }
        }
        else
        {
            Result.RootCompletedAfterCleanup = true;
        }
        Result.ControlDrained = co_await DrainControlWithTimeout(Control, Io.get_executor());
        Result.HandlerInvocations = HandlerInvocations->load(std::memory_order_relaxed);
        Result.ActiveTasksAtCompletion = Root->ActiveTasksAtCompletion;
        co_return Result;
    }

    TEST(MuxService, RejectsMissingStreamHandler)
    {
        Net::io_context Io;
        auto [Raw, Peer] = Preview::MakeMemoryPair(Io.get_executor());
        Preview::Composition::MuxService Service(Preview::Composition::MuxServiceOptions{
            .Mode = Preview::Composition::MuxMode::Smux});
        Code Result = Code::Success;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Preview::Middleware::Context Context;
                Result = co_await Service.Run(
                    std::make_shared<MemoryStream>(std::move(Raw)), Context);
                Peer.Close();
            });
        EXPECT_EQ(Result, Code::NotSupported);
    }

    template <typename Client>
    auto RunOneStreamCase(Net::io_context &Io, const Preview::Composition::MuxMode Mode) -> void
    {
        auto [ServerRaw, ClientRaw] = Preview::MakeMemoryPair(Io.get_executor());
        auto RootWaiting = std::make_shared<AsyncSignal>(Io.get_executor(), 1);
        auto Service = std::make_shared<Preview::Composition::MuxService>(
            Preview::Composition::MuxServiceOptions{
                .Mode = Mode,
                .RootWaitingFn = [RootWaiting]
                {
                    (void)RootWaiting->try_send(boost::system::error_code{});
                }});
        auto StopRequested = std::make_shared<AsyncSignal>(Io.get_executor(), 1);
        Service->SetStreamHandler(
            [Service, StopRequested](Preview::SharedTransmission Stream,
                                     const Preview::Lifecycle::TaskIdentity &)
                -> Net::awaitable<Code>
            {
                EXPECT_TRUE(Stream);
                Service->Stop();
                (void)StopRequested->try_send(boost::system::error_code{});
                co_return Code::Success;
            });
        auto ClientValue = std::make_shared<Client>();
        auto Root = std::make_shared<RootCompletion>(Io.get_executor());
        Code Result = Code::IoError;
        bool Opened = false;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Root->Start(Service, {}, std::make_shared<MemoryStream>(std::move(ServerRaw)));
                EXPECT_TRUE(co_await WaitForSignal(RootWaiting, Io.get_executor()));
                const auto Connected = ClientValue->Connect(
                    std::make_shared<MemoryStream>(std::move(ClientRaw)));
                EXPECT_TRUE(Connected);
                if (!Connected)
                {
                    co_return;
                }
                auto Stream = co_await ClientValue->OpenStream();
                Opened = static_cast<bool>(Stream);
                if (Stream)
                {
                    EXPECT_TRUE(co_await WaitForSignal(StopRequested, Io.get_executor()));
                    Stream->Close();
                }
                ClientValue->Close();
                EXPECT_TRUE(co_await WaitForSignal(Root->SignalValue, Io.get_executor()));
                Result = Root->Result;
            });
        EXPECT_TRUE(Opened);
        EXPECT_EQ(Result, Code::Canceled);
    }

    TEST(MuxService, H2MuxModeUsesH2MuxFraming)
    {
        Net::io_context Io;
        RunOneStreamCase<Preview::Mux::H2Mux::Client<>>(
            Io, Preview::Composition::MuxMode::H2Mux);
    }

    TEST(MuxService, SmuxAcceptsAndOwnsOneChildStream)
    {
        Net::io_context Io;
        RunOneStreamCase<Preview::Mux::Smux::Client<>>(Io, Preview::Composition::MuxMode::Smux);
    }

    TEST(MuxService, YamuxAcceptsAndOwnsOneChildStream)
    {
        Net::io_context Io;
        RunOneStreamCase<Preview::Mux::Yamux::Client<>>(Io, Preview::Composition::MuxMode::Yamux);
    }

    TEST(MuxService, CancelingOneRootDoesNotStopSiblingStreams)
    {
        Net::io_context Io;
        CancelIsolationResult Result;
        Preview::Testing::RunCoro(
            Io,
            [&Io, &Result]() -> Net::awaitable<void>
            {
                Result = co_await RunCancelIsolationCase(Io);
            });

        EXPECT_TRUE(Result.InitialRootAStreamHandled);
        EXPECT_TRUE(Result.InitialRootBStreamHandled);
        EXPECT_TRUE(Result.RootACompleted);
        EXPECT_TRUE(Result.RootADrained);
        EXPECT_FALSE(Result.RootAThrew);
        EXPECT_EQ(Result.RootAResult, Code::Canceled);
        EXPECT_EQ(Result.SiblingStreamsHandled, 2U);
        EXPECT_TRUE(Result.ClientSessionsClosed);
        EXPECT_TRUE(Result.RootBCompleted);
        EXPECT_TRUE(Result.RootBDrained);
        EXPECT_FALSE(Result.RootBThrew);
        EXPECT_EQ(Result.RootBResult, Code::Success);
    }

    TEST(MuxService, RejectedStreamStartClosesRootSession)
    {
        Net::io_context Io;
        StartRejectedResult Result;
        Preview::Testing::RunCoro(
            Io,
            [&Io, &Result]() -> Net::awaitable<void>
            {
                Result = co_await RunStartRejectedCase(Io);
            });

        EXPECT_TRUE(Result.ServerReady);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_TRUE(Result.CloseAccepted);
        EXPECT_TRUE(Result.StreamOpened);
        EXPECT_TRUE(Result.RootCompletedBeforeCleanup);
        EXPECT_FALSE(Result.RootThrew);
        EXPECT_EQ(Result.RootResult, Code::Canceled);
        EXPECT_EQ(Result.HandlerInvocations, 0U);
        EXPECT_GE(Result.StartedBeforeAttempt, 1U);
        EXPECT_EQ(Result.StartedAfterAttempt, Result.StartedBeforeAttempt);
        EXPECT_EQ(Result.ActiveTasksAtCompletion, 0U);
        EXPECT_FALSE(Result.ServerOpenBeforeCleanup);
        EXPECT_TRUE(Result.ClientClosed);
        EXPECT_TRUE(Result.ServerClosedAfterCleanup);
        EXPECT_TRUE(Result.RootCompletedAfterCleanup);
        EXPECT_TRUE(Result.ControlDrained);
    }

    TEST(MuxService, StopWakesIdleRootsAndDrainsChildren)
    {
        Net::io_context Io;
        ServiceStopResult Result;
        Preview::Testing::RunCoro(
            Io,
            [&Io, &Result]() -> Net::awaitable<void>
            {
                Result = co_await RunServiceStopCase(Io);
            });

        EXPECT_TRUE(Result.ClientAConnected);
        EXPECT_TRUE(Result.ClientBConnected);
        EXPECT_TRUE(Result.ChildStarted);
        EXPECT_TRUE(Result.IdleRootWaiting);
        EXPECT_TRUE(Result.RootACompletedOnStop);
        EXPECT_TRUE(Result.RootBCompletedOnStop);
        EXPECT_TRUE(Result.RootAChildFinishedAtCompletion);
        EXPECT_TRUE(Result.RootADrainedOnStop);
        EXPECT_TRUE(Result.RootBDrainedOnStop);
        EXPECT_FALSE(Result.RootAThrew);
        EXPECT_FALSE(Result.RootBThrew);
        EXPECT_EQ(Result.RootAResult, Code::Canceled);
        EXPECT_EQ(Result.RootBResult, Code::Canceled);
        EXPECT_EQ(Result.RootAActiveTasksAtCompletion, 0U);
        EXPECT_EQ(Result.RootBActiveTasksAtCompletion, 0U);
        EXPECT_FALSE(Result.RootADrainBlockedAtCompletion);
        EXPECT_FALSE(Result.RootBDrainBlockedAtCompletion);
        EXPECT_EQ(Result.HandlerInvocations, 1U);
    }

    TEST(MuxService, StopOwnsControlForNoControlRun)
    {
        Net::io_context Io;
        NoControlStopResult Result;
        Preview::Testing::RunCoro(
            Io,
            [&Io, &Result]() -> Net::awaitable<void>
            {
                Result = co_await RunNoControlStopCase(Io);
            });

        EXPECT_TRUE(Result.RootWaiting);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_TRUE(Result.ChildStarted);
        EXPECT_TRUE(Result.RootCompletedOnStop);
        EXPECT_TRUE(Result.ChildFinishedAtCompletion);
        EXPECT_FALSE(Result.RootThrew);
        EXPECT_EQ(Result.RootResult, Code::Canceled);
    }

} // namespace
