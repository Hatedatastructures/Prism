/**
 * @file NetworkingStressTest.cpp
 * @brief 网络层压力测试（T5-10 D7，smoke 版）
 * @details 覆盖：
 *          - TCP 连接风暴：并发 50 连接 × 10 轮，全部 echo 成功
 *          - UDP Relay 长跑：1000 包双向往返
 *          - stress helper：Gate 汇合 / LeakTracker 泄漏探测
 * @note smoke 参数（短时）；完整长跑在 CI/手动扩展轮次
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Net/UdpRelay.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Transport/Unreliable.hpp>
#include <TestSupport/Stress/StressHelper.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using UdpRelayResult = std::expected<void, Preview::Fault::Failure>;

    struct TaskCompletionState final
    {
        TaskCompletionState(Net::any_io_executor Executor, const std::size_t Capacity)
            : Done(std::move(Executor), Capacity)
        {
        }

        CompletionChannel Done;
        std::exception_ptr Failure;
    };

    struct UdpRelayCompletionState final
    {
        UdpRelayCompletionState(Net::any_io_executor Executor, const std::size_t Capacity)
            : Task(std::make_shared<TaskCompletionState>(std::move(Executor), Capacity))
        {
        }

        std::shared_ptr<TaskCompletionState> Task;
        std::optional<UdpRelayResult> Result;
    };

    auto RecordTaskCompletion(const std::shared_ptr<TaskCompletionState> &State,
                              std::exception_ptr Failure) -> void
    {
        if (Failure && !State->Failure)
        {
            State->Failure = Failure;
        }
        (void)State->Done.try_send(boost::system::error_code{});
    }

    auto AwaitTaskCompletion(const std::shared_ptr<TaskCompletionState> &State,
                             const std::size_t Count) -> Net::awaitable<void>
    {
        for (std::size_t Index = 0; Index < Count; ++Index)
        {
            co_await State->Done.async_receive(Net::use_awaitable);
        }
    }

    auto RethrowTaskFailure(const std::shared_ptr<TaskCompletionState> &State) -> void
    {
        if (State->Failure)
        {
            std::rethrow_exception(State->Failure);
        }
    }

    auto RecordUdpRelayCompletion(
        const std::shared_ptr<UdpRelayCompletionState> &State,
        std::exception_ptr Failure,
        UdpRelayResult Result) -> void
    {
        State->Result.emplace(std::move(Result));
        RecordTaskCompletion(State->Task, std::move(Failure));
    }

    auto ExpectUdpRelayCanceled(const UdpRelayResult &Result) -> void
    {
        EXPECT_FALSE(Result.has_value());
        if (Result)
        {
            return;
        }
        EXPECT_EQ(Result.error().Code, Preview::Fault::Code::Canceled);
        EXPECT_EQ(Result.error().Native,
                  static_cast<std::error_code>(Net::error::make_error_code(Net::error::operation_aborted)));
    }

    auto RunCoro(Net::io_context &IoContext, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, std::move(Operation), [&](std::exception_ptr Error)
                      { Failure = Error; });
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /// 长跑缩放因子：NGX_STRESS_DURATION=秒 → 轮次放大（默认 1 = smoke）
    auto StressScale() -> int
    {
        const auto *DurationValue = std::getenv("NGX_STRESS_DURATION");
        if (!DurationValue)
        {
            return 1;
        }
        const auto Seconds = std::atoi(DurationValue);
        if (Seconds <= 0)
        {
            return 1;
        }
        return (std::max)(1, Seconds / 5); // 每 5 秒扩 1 倍
    }

    /// TCP echo 服务器
    auto TcpEchoServer(Tcp::socket Socket) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        boost::system::error_code ErrorCode;
        while (true)
        {
            const auto ReadCount = co_await Socket.async_read_some(Net::buffer(Buffer),
                                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode || ReadCount == 0)
            {
                break;
            }
            co_await Socket.async_write_some(Net::buffer(Buffer, ReadCount),
                                           Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                break;
            }
        }
        Socket.close();
    }

    struct TcpStormState final
    {
        TcpStormState(Net::any_io_executor ExecutorValue, const std::size_t Count)
            : Executor(std::move(ExecutorValue)), ClientGate(Executor, Count),
              ClientDone(std::make_shared<TaskCompletionState>(Executor, Count)),
              SessionDone(std::make_shared<TaskCompletionState>(Executor, Count)),
              AcceptDone(std::make_shared<TaskCompletionState>(Executor, 1)), Total(Count)
        {
        }

        Net::any_io_executor Executor;
        std::unique_ptr<Tcp::acceptor> Acceptor;
        Preview::Stress::Gate ClientGate;
        std::shared_ptr<TaskCompletionState> ClientDone;
        std::shared_ptr<TaskCompletionState> SessionDone;
        std::shared_ptr<TaskCompletionState> AcceptDone;
        std::atomic<std::size_t> Accepted{0};
        std::atomic<int> Successful{0};
        std::size_t Total;
    };

    auto RunTcpAcceptLoop(const std::shared_ptr<TcpStormState> &State) -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ErrorCode;
            auto Socket = co_await State->Acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
            State->Accepted.fetch_add(1, std::memory_order_relaxed);
            Net::co_spawn(
                State->Executor,
                TcpEchoServer(std::move(Socket)),
                [State](std::exception_ptr Failure)
                { RecordTaskCompletion(State->SessionDone, Failure); });
        }
    }

    /** @brief 等待压测连接真实关闭和活动退栈，避免客户端完成通知早于资源退休。 */
    auto RetireStormConnection(Preview::SharedTransmission Connection) -> Net::awaitable<void>
    {
        if (!Connection) co_return;
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        EXPECT_TRUE(Connection->Cancel());
        EXPECT_TRUE(Connection->Close());
        const auto Activity = Connection->Activity();
        EXPECT_TRUE(Activity);
        if (Activity) EXPECT_TRUE(co_await Activity->Drain());
    }

    auto RunTcpStormClient(const std::shared_ptr<TcpStormState> &State, const int Index)
        -> Net::awaitable<void>
    {
        Preview::SharedTransmission Connection;
        std::exception_ptr Failure;
        try
        {
            Preview::Network::Dialer::Dialer Dialer(State->Executor);
            auto Connected = co_await Dialer.Connect({
                *Preview::Network::ParseHost("127.0.0.1"), State->Acceptor->local_endpoint().port()});
            if (Connected)
            {
                Connection = std::move(*Connected);
                const std::string Message = "storm-" + std::to_string(Index);
                const auto Written = co_await Connection->WriteExact(Preview::AsBytesSpan(Message));
                std::array<std::byte, 64> Buffer{};
                const auto Read = co_await Connection->ReadExact(std::span(Buffer).first(Message.size()));
                if (Written.Failure.Succeeded() && Written.Bytes == Message.size() &&
                    Read.Failure.Succeeded() && Read.Bytes == Message.size() &&
                    std::string_view(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes) == Message)
                {
                    State->Successful.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
        co_await RetireStormConnection(std::move(Connection));
        State->ClientGate.Arrive();
        if (Failure) std::rethrow_exception(Failure);
    }

    auto RunTcpStormScenario(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        constexpr int ConnectionsPerRound = 50;
        const auto Rounds = 10 * StressScale();
        const auto Total = static_cast<std::size_t>(ConnectionsPerRound * Rounds);
        auto State = std::make_shared<TcpStormState>(IoContext.get_executor(), Total);
        State->Acceptor = std::make_unique<Tcp::acceptor>(
            IoContext, Tcp::endpoint(Tcp::v4(), 0));

        Net::co_spawn(
            State->Executor,
            RunTcpAcceptLoop(State),
            [State](std::exception_ptr Failure)
            { RecordTaskCompletion(State->AcceptDone, Failure); });
        for (int Round = 0; Round < Rounds; ++Round)
        {
            for (int Index = 0; Index < ConnectionsPerRound; ++Index)
            {
                const auto ClientIndex = Index;
                Net::co_spawn(
                    State->Executor,
                    RunTcpStormClient(State, ClientIndex),
                    [State](std::exception_ptr Failure)
                    { RecordTaskCompletion(State->ClientDone, Failure); });
            }
        }
        co_await State->ClientGate.Wait();
        boost::system::error_code CloseError;
        State->Acceptor->close(CloseError);
        co_await AwaitTaskCompletion(State->AcceptDone, 1);
        co_await AwaitTaskCompletion(State->ClientDone, Total);
        co_await AwaitTaskCompletion(State->SessionDone, State->Accepted.load(std::memory_order_acquire));
        RethrowTaskFailure(State->AcceptDone);
        RethrowTaskFailure(State->ClientDone);
        RethrowTaskFailure(State->SessionDone);
        EXPECT_EQ(State->Successful.load(std::memory_order_acquire), static_cast<int>(Total));
    }

    auto RunUdpRelayTask(const std::shared_ptr<Preview::Transport::Unreliable> &EndpointA,
                         const std::shared_ptr<Preview::Transport::Unreliable> &EndpointB)
        -> Net::awaitable<UdpRelayResult>
    {
        Preview::Network::Udp::RelayOptions OptionsValue;
        OptionsValue.IdleTimeout = std::chrono::milliseconds(5000);
        Preview::Network::Udp::UdpRelay Relay(EndpointA, EndpointB, OptionsValue);
        co_return co_await Relay.Run();
    }

    struct UdpLearningRequest final
    {
        Net::ip::udp::socket &ClientSocketA;
        Net::ip::udp::socket &ClientSocketB;
        Net::ip::udp::endpoint RelayEndpointA;
        Net::ip::udp::endpoint RelayEndpointB;
    };

    auto RunUdpLearning(UdpLearningRequest Request) -> Net::awaitable<void>
    {
        const std::string LearnPayload = "l";
        boost::system::error_code ErrorCode;
        co_await Request.ClientSocketA.async_send_to(
            Net::buffer(LearnPayload.data(), LearnPayload.size()), Request.RelayEndpointA,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_await Request.ClientSocketB.async_send_to(
            Net::buffer(LearnPayload.data(), LearnPayload.size()), Request.RelayEndpointB,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        std::array<std::byte, 8> Buffer{};
        Net::ip::udp::endpoint Source;
        co_await Request.ClientSocketA.async_receive_from(
            Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, ErrorCode));
        EXPECT_FALSE(ErrorCode);
    }

    auto RunUdpEchoClient(Net::ip::udp::socket &ClientSocketB, const int PacketCount)
        -> Net::awaitable<void>
    {
        for (int Index = 0; Index < PacketCount; ++Index)
        {
            std::array<std::byte, 64> Buffer{};
            Net::ip::udp::endpoint Source;
            boost::system::error_code ErrorCode;
            const auto Count = co_await ClientSocketB.async_receive_from(
                Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode || Count == 0)
            {
                co_return;
            }
            co_await ClientSocketB.async_send_to(
                Net::buffer(Buffer, Count), Source, Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
        }
    }

    auto RunUdpPacketExchange(Net::ip::udp::socket &ClientSocketA,
                              const Net::ip::udp::endpoint RelayEndpointA,
                              const int PacketCount) -> Net::awaitable<void>
    {
        int Received = 0;
        for (int Index = 0; Index < PacketCount; ++Index)
        {
            const std::string Message = "udp-" + std::to_string(Index);
            boost::system::error_code ErrorCode;
            co_await ClientSocketA.async_send_to(
                Net::buffer(Message.data(), Message.size()), RelayEndpointA,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            std::array<std::byte, 64> Buffer{};
            Net::ip::udp::endpoint Source;
            const auto Count = co_await ClientSocketA.async_receive_from(
                Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (!ErrorCode && Count == Message.size() &&
                std::string_view(reinterpret_cast<const char *>(Buffer.data()), Count) == Message)
            {
                ++Received;
            }
        }
        EXPECT_EQ(Received, PacketCount);
    }

    auto RunUdpRelayScenario(Net::io_context &IoContext, const int PacketCount) -> Net::awaitable<void>
    {
        auto EndpointA = std::make_shared<Preview::Transport::Unreliable>(IoContext.get_executor());
        auto EndpointB = std::make_shared<Preview::Transport::Unreliable>(IoContext.get_executor());
        boost::system::error_code ErrorCode;
        EndpointA->NativeSocket().open(Net::ip::udp::v4(), ErrorCode);
        EndpointA->NativeSocket().bind(
            Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), ErrorCode);
        EndpointB->NativeSocket().open(Net::ip::udp::v4(), ErrorCode);
        EndpointB->NativeSocket().bind(
            Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), ErrorCode);

        Net::ip::udp::socket ClientSocketA(IoContext.get_executor());
        Net::ip::udp::socket ClientSocketB(IoContext.get_executor());
        ClientSocketA.open(Net::ip::udp::v4(), ErrorCode);
        ClientSocketA.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), ErrorCode);
        ClientSocketB.open(Net::ip::udp::v4(), ErrorCode);
        ClientSocketB.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), ErrorCode);

        const auto RelayEndpointA = EndpointA->NativeSocket().local_endpoint();
        const auto RelayEndpointB = EndpointB->NativeSocket().local_endpoint();
        const auto RelayCompletion = std::make_shared<UdpRelayCompletionState>(IoContext.get_executor(), 1);
        const auto EchoCompletion = std::make_shared<TaskCompletionState>(IoContext.get_executor(), 1);
        Net::co_spawn(
            IoContext.get_executor(), RunUdpRelayTask(EndpointA, EndpointB),
            [RelayCompletion](std::exception_ptr Failure, UdpRelayResult Result)
            { RecordUdpRelayCompletion(RelayCompletion, std::move(Failure), std::move(Result)); });

        co_await RunUdpLearning(UdpLearningRequest{
            ClientSocketA, ClientSocketB, RelayEndpointA, RelayEndpointB});
        Net::co_spawn(
            IoContext.get_executor(), RunUdpEchoClient(ClientSocketB, PacketCount),
            [EchoCompletion](std::exception_ptr Failure)
            { RecordTaskCompletion(EchoCompletion, Failure); });
        co_await RunUdpPacketExchange(ClientSocketA, RelayEndpointA, PacketCount);
        co_await AwaitTaskCompletion(EchoCompletion, 1);

        boost::system::error_code CloseError;
        ClientSocketA.close(CloseError);
        ClientSocketB.close(CloseError);
        const auto CloseA = EndpointA->Close();
        EXPECT_TRUE(CloseA);
        const auto CloseB = EndpointB->Close();
        EXPECT_TRUE(CloseB);
        co_await AwaitTaskCompletion(RelayCompletion->Task, 1);
        RethrowTaskFailure(EchoCompletion);
        RethrowTaskFailure(RelayCompletion->Task);
        EXPECT_TRUE(RelayCompletion->Result.has_value());
        if (RelayCompletion->Result)
        {
            ExpectUdpRelayCanceled(*RelayCompletion->Result);
        }
    }

    /**
     * @brief 验证 Gate 在三个到达者完成后才释放等待者。
     * @param IoContext 场景使用的 IO 上下文。
     * @return 汇合断言完成后返回。
     */
    auto RunGateScenario(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        Preview::Stress::Gate GateValue(IoContext.get_executor(), 3);
        std::atomic<int> Arrived{0};
        for (int Index = 0; Index < 3; ++Index)
        {
            ++Arrived;
            GateValue.Arrive();
        }
        co_await GateValue.Wait();
        EXPECT_EQ(Arrived, 3);
    }

    TEST(NetworkStress, TcpConnectionStorm)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunTcpStormScenario(IoContext));
    }

    TEST(NetworkStress, UdpRelayLongRun)
    {
        const auto PacketCount = 1000 * StressScale();
        Net::io_context IoContext;
        RunCoro(IoContext, RunUdpRelayScenario(IoContext, PacketCount));
    }

    TEST(NetworkStress, LeakTrackerDetectsRelease)
    {
        auto Object = std::make_shared<int>(42);
        Preview::Stress::LeakTracker Tracker;
        Tracker.Track(Object);
        EXPECT_EQ(Tracker.Total(), 1);
        EXPECT_FALSE(Tracker.AllReleased());
        Object.reset();
        EXPECT_TRUE(Tracker.AllReleased());
    }

    TEST(NetworkStress, GateSynchronizes)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunGateScenario(IoContext));
    }

} // namespace
