/**
 * @file UdpRelayTest.cpp
 * @brief UDP 双向中继测试（T3-4 D5 完整版）
 * @details 覆盖：
 *          - 动态关联：首包学习 → 配对 → 双向转发（echo 往返）
 *          - 关联超时回收：会话空闲超时后不再转发
 *          - 端口不匹配：未配对来源包丢弃
 *          - 单侧关闭：任一端 socket 关闭 → 隧道终止
 * @note 使用 loopback UDP socket；客户端来源动态学习（无需预置）
 */

#include <Prism/Net/UdpRelay.hpp>
#include <Prism/Transport/Unreliable.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using UdpRelayResult = std::expected<void, Prism::Fault::Failure>;

    struct UdpRelayStartRequest final
    {
        Net::io_context &IoContext;
        std::shared_ptr<Prism::Transport::Unreliable> EndpointA;
        std::shared_ptr<Prism::Transport::Unreliable> EndpointB;
        Prism::Network::Udp::RelayOptions Options;
    };

    struct UdpRelayCompletion final
    {
        explicit UdpRelayCompletion(Net::any_io_executor Executor)
            : Ready(std::move(Executor), 1)
        {
        }

        auto Complete(std::exception_ptr Error, UdpRelayResult Value) -> void
        {
            Exception = std::move(Error);
            Result.emplace(std::move(Value));
            Completed = true;
            (void)Ready.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto IsCompleted() const noexcept -> bool
        {
            return Completed;
        }

        [[nodiscard]] auto Wait() -> Net::awaitable<UdpRelayResult>
        {
            if (!Completed)
            {
                co_await Ready.async_receive(Net::use_awaitable);
            }
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
            if (!Result)
            {
                throw std::logic_error("UDP relay completion had no result");
            }
            co_return std::move(*Result);
        }

        Net::experimental::channel<void(boost::system::error_code)> Ready;
        std::exception_ptr Exception;
        std::optional<UdpRelayResult> Result;
        bool Completed{false};
    };

    [[nodiscard]] auto RunUdpRelay(UdpRelayStartRequest Request)
        -> Net::awaitable<UdpRelayResult>
    {
        Prism::Network::Udp::UdpRelay Relay(
            std::move(Request.EndpointA), std::move(Request.EndpointB), Request.Options);
        co_return co_await Relay.Run();
    }

    [[nodiscard]] auto StartUdpRelay(UdpRelayStartRequest Request)
        -> std::shared_ptr<UdpRelayCompletion>
    {
        auto Completion = std::make_shared<UdpRelayCompletion>(
            Request.IoContext.get_executor());
        Net::co_spawn(
            Request.IoContext, RunUdpRelay(std::move(Request)),
            [Completion](std::exception_ptr Error, UdpRelayResult Result)
            {
                Completion->Complete(std::move(Error), std::move(Result));
            });
        return Completion;
    }

    auto ExpectRelayCanceled(const UdpRelayResult &Result) -> void
    {
        EXPECT_FALSE(Result.has_value());
        if (Result)
        {
            return;
        }
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Result.error().Native,
                  static_cast<std::error_code>(Net::error::make_error_code(Net::error::operation_aborted)));
    }

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error)
                      { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /**
     * @brief 带超时的 UDP 收包
     * @return true = 收到（out 填充）；false = 超时/错误
     */
    auto ReceiveWithTimeout(Net::ip::udp::socket &Socket, std::string &Output,
                            std::chrono::milliseconds Timeout) -> Net::awaitable<bool>
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        std::array<std::byte, 256> Buffer{};
        Net::ip::udp::endpoint Src;
        boost::system::error_code Ec;
        Net::steady_timer Timer(Socket.get_executor());
        Timer.expires_after(Timeout);
        auto Result = co_await (Socket.async_receive_from(Net::buffer(Buffer), Src,
                                                          Net::redirect_error(Net::use_awaitable, Ec)) ||
                                Timer.async_wait(Net::use_awaitable));
        if (Result.index() == 1 || Ec)
        {
            co_return false; // 超时/错误 = 未收到
        }
        Output.assign(reinterpret_cast<const char *>(Buffer.data()), std::get<0>(Result));
        co_return true;
    }

    auto VerifyZeroLengthDatagramForwarded(
        Net::ip::udp::socket &Source,
        const Net::ip::udp::endpoint &Target,
        Net::ip::udp::socket &Destination) -> Net::awaitable<bool>
    {
        std::array<std::byte, 1> EmptyDatagram{};
        boost::system::error_code Error;
        const auto Sent = co_await Source.async_send_to(
            Net::buffer(EmptyDatagram.data(), 0U), Target,
            Net::redirect_error(Net::use_awaitable, Error));
        EXPECT_FALSE(Error);
        EXPECT_EQ(Sent, 0U);
        std::string Received{"not-empty"};
        const auto ReceivedInTime = co_await ReceiveWithTimeout(
            Destination, Received, std::chrono::milliseconds(300));
        EXPECT_TRUE(ReceivedInTime);
        EXPECT_TRUE(Received.empty());
        co_return ReceivedInTime;
    }

    auto StopUdpRelay(
        const std::shared_ptr<Prism::Transport::Unreliable> &Endpoint,
        const std::shared_ptr<UdpRelayCompletion> &RelayTask) -> Net::awaitable<void>
    {
        EXPECT_TRUE(Endpoint->Close());
        ExpectRelayCanceled(co_await RelayTask->Wait());
    }

    auto EchoNextNonemptyDatagram(
        Net::ip::udp::socket &Socket, std::string &Observed) -> Net::awaitable<void>
    {
        std::array<std::byte, 256> Buffer{};
        Net::ip::udp::endpoint Source;
        boost::system::error_code Error;
        while (true)
        {
            const auto Count = co_await Socket.async_receive_from(
                Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, Error));
            if (Error) co_return;
            if (Count == 0U) continue;
            Observed.assign(reinterpret_cast<const char *>(Buffer.data()), Count);
            co_await Socket.async_send_to(Net::buffer(Buffer, Count), Source,
                Net::redirect_error(Net::use_awaitable, Error));
            co_return;
        }
    }

    struct UdpRelayAssociationPair final
    {
        const Net::ip::udp::endpoint &EndpointA;
        const Net::ip::udp::endpoint &EndpointB;
        std::shared_ptr<Prism::Transport::Unreliable> RelayEndpoint;
        std::shared_ptr<UdpRelayCompletion> RelayTask;
        Net::ip::udp::socket &ClientA;
        Net::ip::udp::socket &ClientB;
    };

    using AssociationAndEchoRequest = UdpRelayAssociationPair;

    struct UdpRelayAssociationScenario final
    {
        UdpRelayAssociationPair Pair;
        Net::io_context& IoContext;
        boost::system::error_code& Error;
    };

    struct AssociationAndEchoResult final
    {
        std::string EchoBack;
        std::string ReceivedByA;
        bool EmptyDatagramForwarded{false};
    };

    auto RunAssociationAndEcho(AssociationAndEchoRequest Request)
        -> Net::awaitable<AssociationAndEchoResult>
    {
        AssociationAndEchoResult Result;
        boost::system::error_code Error;

        const std::string LearnA = "learn-a";
        co_await Request.ClientA.async_send_to(Net::buffer(LearnA), Request.EndpointA,
                                               Net::redirect_error(Net::use_awaitable, Error));
        const std::string LearnB = "learn-b";
        co_await Request.ClientB.async_send_to(
            Net::buffer(LearnB), Request.EndpointB,
            Net::redirect_error(Net::use_awaitable, Error));
        std::array<std::byte, 256> Buffer{};
        Net::ip::udp::endpoint Source;
        const auto LearnBCount = co_await Request.ClientA.async_receive_from(
            Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, Error));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), LearnBCount), LearnB);

        Result.EmptyDatagramForwarded = co_await VerifyZeroLengthDatagramForwarded(
            Request.ClientA, Request.EndpointA, Request.ClientB);
        if (!Result.EmptyDatagramForwarded)
        {
            co_await StopUdpRelay(Request.RelayEndpoint, Request.RelayTask);
            Request.ClientB.close(Error);
            co_return Result;
        }
        Net::co_spawn(Request.ClientB.get_executor(),
            EchoNextNonemptyDatagram(Request.ClientB, Result.EchoBack), Net::detached);

        const std::string Message = "echo-me";
        co_await Request.ClientA.async_send_to(Net::buffer(Message), Request.EndpointA,
                                               Net::redirect_error(Net::use_awaitable, Error));
        for (int Index = 0; Index < 50 && Result.EchoBack.empty(); ++Index)
        {
            Net::steady_timer Timer(Request.ClientA.get_executor());
            Timer.expires_after(std::chrono::milliseconds(10));
            co_await Timer.async_wait(Net::use_awaitable);
        }
        EXPECT_EQ(Result.EchoBack, Message);
        const auto EchoCount = co_await Request.ClientA.async_receive_from(
            Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, Error));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), EchoCount), Message);
        Result.ReceivedByA.assign(reinterpret_cast<const char *>(Buffer.data()), EchoCount);

        EXPECT_TRUE(Request.RelayEndpoint->Close());
        ExpectRelayCanceled(co_await Request.RelayTask->Wait());
        co_return Result;
    }

    struct AssociationTimeoutReapRequest final
    {
        UdpRelayAssociationScenario Association;
        bool& ForwardedAfterReap;
    };

    auto RunAssociationTimeoutReap(AssociationTimeoutReapRequest Request)
        -> Net::awaitable<void>
    {
        const auto& Pair = Request.Association.Pair;
        const std::string Learn = "l";
        co_await Pair.ClientA.async_send_to(Net::buffer(Learn.data(), Learn.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        co_await Pair.ClientB.async_send_to(Net::buffer(Learn.data(), Learn.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));

        std::array<std::byte, 64> Buffer{};
        Net::ip::udp::endpoint Source;
        co_await Pair.ClientA.async_receive_from(Net::buffer(Buffer), Source,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));

        Net::steady_timer ReapTimer(Request.Association.IoContext);
        ReapTimer.expires_after(std::chrono::milliseconds(200));
        co_await ReapTimer.async_wait(Net::use_awaitable);

        const std::string AfterReap = "after-Reap";
        co_await Pair.ClientB.async_send_to(Net::buffer(AfterReap.data(), AfterReap.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        Net::steady_timer ForwardingWindow(Request.Association.IoContext);
        ForwardingWindow.expires_after(std::chrono::milliseconds(100));
        co_await ForwardingWindow.async_wait(Net::use_awaitable);
        Request.ForwardedAfterReap = true;

        const auto StopResult = Pair.RelayEndpoint->Close();
        EXPECT_TRUE(StopResult);
        const auto RelayResult = co_await Pair.RelayTask->Wait();
        ExpectRelayCanceled(RelayResult);
    }

    struct DatagramObservationRequest final
    {
        Net::ip::udp::socket& Socket;
        bool& Received;
    };

    auto ObserveNonemptyDatagram(DatagramObservationRequest Request)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 128> Buffer{};
        Net::ip::udp::endpoint Source;
        boost::system::error_code Error;
        const auto Count = co_await Request.Socket.async_receive_from(
            Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, Error));
        if (Count > 0) Request.Received = true;
        co_return;
    }

    struct PortMismatchRequest final
    {
        UdpRelayAssociationScenario Association;
        Net::ip::udp::socket& Stranger;
        bool& Received;
        bool& StrangerDropped;
    };

    auto RunPortMismatchScenario(PortMismatchRequest Request) -> Net::awaitable<void>
    {
        const auto& Pair = Request.Association.Pair;
        Net::co_spawn(Request.Association.IoContext.get_executor(),
            ObserveNonemptyDatagram({Pair.ClientB, Request.Received}), Net::detached);

        const std::string Learn = "l";
        co_await Pair.ClientA.async_send_to(Net::buffer(Learn.data(), Learn.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        co_await Pair.ClientB.async_send_to(Net::buffer(Learn.data(), Learn.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        std::array<std::byte, 64> Buffer{};
        Net::ip::udp::endpoint Source;
        co_await Pair.ClientA.async_receive_from(Net::buffer(Buffer), Source,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));

        const std::string Evil = "evil";
        co_await Request.Stranger.async_send_to(Net::buffer(Evil.data(), Evil.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        Net::steady_timer StrangerWindow(Request.Association.IoContext);
        StrangerWindow.expires_after(std::chrono::milliseconds(100));
        co_await StrangerWindow.async_wait(Net::use_awaitable);

        const std::string Good = "good";
        co_await Pair.ClientA.async_send_to(Net::buffer(Good.data(), Good.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        for (int Index = 0; Index < 50 && !Request.Received; ++Index)
        {
            Net::steady_timer ReceivePoll(Request.Association.IoContext);
            ReceivePoll.expires_after(std::chrono::milliseconds(10));
            co_await ReceivePoll.async_wait(Net::use_awaitable);
        }
        Request.StrangerDropped = Request.Received;

        const auto StopResult = Pair.RelayEndpoint->Close();
        EXPECT_TRUE(StopResult);
        const auto RelayResult = co_await Pair.RelayTask->Wait();
        ExpectRelayCanceled(RelayResult);
    }

    struct EndCloseRequest final
    {
        Net::io_context& IoContext;
        std::shared_ptr<Prism::Transport::Unreliable> RelayEndpoint;
        std::shared_ptr<UdpRelayCompletion> RelayTask;
        bool& RelayDone;
    };

    auto RunEndCloseScenario(EndCloseRequest Request) -> Net::awaitable<void>
    {
        Net::steady_timer InitialDelay(Request.IoContext);
        InitialDelay.expires_after(std::chrono::milliseconds(50));
        co_await InitialDelay.async_wait(Net::use_awaitable);

        const auto StopResult = Request.RelayEndpoint->Close();
        EXPECT_TRUE(StopResult);
        for (int Index = 0; Index < 100 && !Request.RelayTask->IsCompleted(); ++Index)
        {
            Net::steady_timer CompletionPoll(Request.IoContext);
            CompletionPoll.expires_after(std::chrono::milliseconds(10));
            co_await CompletionPoll.async_wait(Net::use_awaitable);
        }
        if (Request.RelayTask->IsCompleted())
        {
            const auto RelayResult = co_await Request.RelayTask->Wait();
            ExpectRelayCanceled(RelayResult);
            Request.RelayDone = true;
        }
    }

    auto RunBFirstOrphanScenario(UdpRelayAssociationScenario Request) -> Net::awaitable<void>
    {
        const auto& Pair = Request.Pair;
        const std::string Orphan = "orphan-b";
        co_await Pair.ClientB.async_send_to(Net::buffer(Orphan.data(), Orphan.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Error));
        Net::steady_timer ReapTimer(Request.IoContext);
        ReapTimer.expires_after(std::chrono::milliseconds(200));
        co_await ReapTimer.async_wait(Net::use_awaitable);

        const std::string Probe = "stale-pair-probe";
        co_await Pair.ClientA.async_send_to(Net::buffer(Probe.data(), Probe.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Error));
        std::string Received;
        EXPECT_FALSE(co_await ReceiveWithTimeout(
            Pair.ClientB, Received, std::chrono::milliseconds(150)))
            << "陈旧 B 端点不应与新 A 来源配对，收到=" << Received;

        const auto StopResult = Pair.RelayEndpoint->Close();
        EXPECT_TRUE(StopResult);
        const auto RelayResult = co_await Pair.RelayTask->Wait();
        ExpectRelayCanceled(RelayResult);
    }

    struct AssociationLimitRequest final
    {
        UdpRelayAssociationScenario Association;
        Net::ip::udp::socket& A2;
        Net::ip::udp::socket& B2;
    };

    auto RunAssociationLimitScenario(AssociationLimitRequest Request) -> Net::awaitable<void>
    {
        const auto& Pair = Request.Association.Pair;
        const std::string Hello = "s1-hello";
        co_await Pair.ClientA.async_send_to(Net::buffer(Hello.data(), Hello.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        co_await Pair.ClientB.async_send_to(Net::buffer(Hello.data(), Hello.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        std::string Received;
        EXPECT_TRUE(co_await ReceiveWithTimeout(
            Pair.ClientA, Received, std::chrono::milliseconds(300)))
            << "会话 1 配对后应收到 B1 首包";

        co_await Request.A2.async_send_to(Net::buffer(Hello.data(), Hello.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        co_await Request.B2.async_send_to(Net::buffer(Hello.data(), Hello.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        std::string Leaked;
        EXPECT_FALSE(co_await ReceiveWithTimeout(
            Request.A2, Leaked, std::chrono::milliseconds(150)))
            << "超出 MaxAssociations 的新会话不应建立，收到=" << Leaked;

        const std::string Again = "s1-again";
        co_await Pair.ClientA.async_send_to(Net::buffer(Again.data(), Again.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        std::string ReceivedAgain;
        EXPECT_TRUE(co_await ReceiveWithTimeout(
            Pair.ClientB, ReceivedAgain, std::chrono::milliseconds(300)))
            << "已有会话不应受新会话拒绝影响";
        EXPECT_EQ(ReceivedAgain, Again);

        const auto StopResult = Request.Association.Pair.RelayEndpoint->Close();
        EXPECT_TRUE(StopResult);
        const auto RelayResult = co_await Request.Association.Pair.RelayTask->Wait();
        ExpectRelayCanceled(RelayResult);
    }

    struct OneSidedTrafficRequest final
    {
        UdpRelayAssociationScenario Association;
        Net::ip::udp::socket& Intruder;
    };

    auto RunOneSidedTrafficScenario(OneSidedTrafficRequest Request)
        -> Net::awaitable<void>
    {
        const auto& Pair = Request.Association.Pair;
        const std::string Learn = "learn";
        co_await Pair.ClientA.async_send_to(Net::buffer(Learn.data(), Learn.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        co_await Pair.ClientB.async_send_to(Net::buffer(Learn.data(), Learn.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        std::string Received;
        EXPECT_TRUE(co_await ReceiveWithTimeout(
            Pair.ClientA, Received, std::chrono::milliseconds(300)));

        const std::string Keep = "keep";
        for (int Index = 0; Index < 5; ++Index)
        {
            co_await Pair.ClientB.async_send_to(Net::buffer(Keep.data(), Keep.size()), Pair.EndpointB,
                Net::redirect_error(Net::use_awaitable, Request.Association.Error));
            Net::steady_timer KeepAliveTick(Request.Association.IoContext);
            KeepAliveTick.expires_after(std::chrono::milliseconds(40));
            co_await KeepAliveTick.async_wait(Net::use_awaitable);
        }

        const std::string Intruder = "intruder-a2";
        co_await Request.Intruder.async_send_to(Net::buffer(Intruder.data(), Intruder.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        co_await Pair.ClientB.async_send_to(Net::buffer(Keep.data(), Keep.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        std::string Leaked;
        EXPECT_FALSE(co_await ReceiveWithTimeout(
            Pair.ClientB, Leaked, std::chrono::milliseconds(40)))
            << "仅 B 侧活跃不应导致会话被回收并与新 A 来源配对，收到=" << Leaked;

        co_await Pair.ClientB.async_send_to(Net::buffer(Keep.data(), Keep.size()), Pair.EndpointB,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        const std::string Probe = "after-one-sided";
        co_await Pair.ClientA.async_send_to(Net::buffer(Probe.data(), Probe.size()), Pair.EndpointA,
            Net::redirect_error(Net::use_awaitable, Request.Association.Error));
        std::string ReceivedAgain;
        EXPECT_TRUE(co_await ReceiveWithTimeout(
            Pair.ClientB, ReceivedAgain, std::chrono::milliseconds(300)))
            << "原会话应保持可用";
        EXPECT_EQ(ReceivedAgain, Probe);

        const auto StopResult = Pair.RelayEndpoint->Close();
        EXPECT_TRUE(StopResult);
        const auto RelayResult = co_await Pair.RelayTask->Wait();
        ExpectRelayCanceled(RelayResult);
    }
} // namespace

TEST(UdpRelay, AssociationAndEcho)
{
    Net::io_context ioc;

    auto a = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    // 中继 A↔B（动态关联）
    Prism::Network::Udp::RelayOptions RelayOptionsValue;
    RelayOptionsValue.IdleTimeout = std::chrono::milliseconds(0); // 禁用回收
    const auto RelayTask = StartUdpRelay({ioc, a, b, RelayOptionsValue});

    // 外部端 client_a（连 A 侧）、client_b（连 B 侧）
    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    // cb 侧回显
    std::optional<AssociationAndEchoResult> Outcome;
    RunCoro(ioc, [&]() -> Net::awaitable<void>
    {
        Outcome.emplace(co_await RunAssociationAndEcho(
            AssociationAndEchoRequest{a_ep, b_ep, a, RelayTask, client_a, client_b}));
    }());

    ASSERT_TRUE(Outcome);
    EXPECT_TRUE(Outcome->EmptyDatagramForwarded);
    EXPECT_EQ(Outcome->EchoBack, "echo-me");
    EXPECT_EQ(Outcome->ReceivedByA, "echo-me");
}

TEST(UdpRelay, AssociationTimeoutReap)
{
    Net::io_context ioc;

    auto a = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Prism::Network::Udp::RelayOptions RelayOptionsValue;
    RelayOptionsValue.IdleTimeout = std::chrono::milliseconds(80); // 80ms 回收
    const auto RelayTask = StartUdpRelay({ioc, a, b, RelayOptionsValue});

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);

    bool forwarded_after_reap = false;
    RunCoro(ioc, RunAssociationTimeoutReap(
        {{{a_ep, b_ep, a, RelayTask, client_a, client_b}, ioc, oec}, forwarded_after_reap}));
    EXPECT_TRUE(forwarded_after_reap);
}

TEST(UdpRelay, PortMismatchDropped)
{
    Net::io_context ioc;

    auto a = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Prism::Network::Udp::RelayOptions RelayOptionsValue;
    RelayOptionsValue.IdleTimeout = std::chrono::milliseconds(0);
    const auto RelayTask = StartUdpRelay({ioc, a, b, RelayOptionsValue});

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    Net::ip::udp::socket stranger(ioc.get_executor()); // 未关联来源
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    stranger.open(Net::ip::udp::v4(), oec);
    stranger.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    bool received = false;
    bool stranger_dropped = true;
    RunCoro(ioc, RunPortMismatchScenario(
        {{{a_ep, b_ep, a, RelayTask, client_a, client_b}, ioc, oec}, stranger, received, stranger_dropped}));
    EXPECT_TRUE(received);
    EXPECT_TRUE(stranger_dropped);
}

TEST(UdpRelay, EndCloseTerminates)
{
    Net::io_context ioc;

    auto a = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    bool RelayDone = false;
    Prism::Network::Udp::RelayOptions RelayOptionsValue;
    RelayOptionsValue.IdleTimeout = std::chrono::milliseconds(0); // 禁用回收，只验证关闭语义
    const auto RelayTask = StartUdpRelay({ioc, a, b, RelayOptionsValue});

    // 关闭 A 端 → 隧道终止
    RunCoro(ioc, RunEndCloseScenario({ioc, a, RelayTask, RelayDone}));
    EXPECT_TRUE(RelayDone);
}

TEST(UdpRelay, BFirstOrphanReapedNotReused)
{
    // P-H03：B 先到且未配对的孤立条目必须被对称回收；
    // 否则后续新 A 来源会与陈旧 B 端点配对，造成跨会话流量混淆。
    Net::io_context ioc;
    auto a = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);
    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Prism::Network::Udp::RelayOptions RelayOptionsValue;
    RelayOptionsValue.IdleTimeout = std::chrono::milliseconds(60);
    RelayOptionsValue.MaxAssociations = 8;
    const auto RelayTask = StartUdpRelay({ioc, a, b, RelayOptionsValue});

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    RunCoro(ioc, RunBFirstOrphanScenario(
        {{a_ep, b_ep, a, RelayTask, client_a, client_b}, ioc, oec}));
}

TEST(UdpRelay, AssociationLimitRejectsNewPair)
{
    // P-H03：关联数达到上限后新会话必须被拒绝，已有会话保持可用。
    Net::io_context ioc;
    auto a = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);
    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Prism::Network::Udp::RelayOptions RelayOptionsValue;
    RelayOptionsValue.IdleTimeout = std::chrono::milliseconds(0); // 禁用回收，隔离上限行为
    RelayOptionsValue.MaxAssociations = 1;
    const auto RelayTask = StartUdpRelay({ioc, a, b, RelayOptionsValue});

    auto make_client = [&](Net::ip::udp::socket &s)
    {
        boost::system::error_code ec;
        s.open(Net::ip::udp::v4(), ec);
        s.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), ec);
        EXPECT_FALSE(ec);
    };
    Net::ip::udp::socket a1(ioc.get_executor());
    Net::ip::udp::socket b1(ioc.get_executor());
    Net::ip::udp::socket a2(ioc.get_executor());
    Net::ip::udp::socket b2(ioc.get_executor());
    make_client(a1);
    make_client(b1);
    make_client(a2);
    make_client(b2);

    RunCoro(ioc, RunAssociationLimitScenario(
        {{{a_ep, b_ep, a, RelayTask, a1, b1}, ioc, oec}, a2, b2}));
}

TEST(UdpRelay, OneSidedTrafficKeepsSessionAlive)
{
    // P-H03：仅一侧持续发流量时，会话不能因另一侧时间戳陈旧被误回收。
    Net::io_context ioc;
    auto a = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    auto b = std::make_shared<Prism::Transport::Unreliable>(ioc.get_executor());
    boost::system::error_code oec;
    a->NativeSocket().open(Net::ip::udp::v4(), oec);
    a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    b->NativeSocket().open(Net::ip::udp::v4(), oec);
    b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);
    const auto a_ep = a->NativeSocket().local_endpoint();
    const auto b_ep = b->NativeSocket().local_endpoint();

    Prism::Network::Udp::RelayOptions RelayOptionsValue;
    RelayOptionsValue.IdleTimeout = std::chrono::milliseconds(60);
    RelayOptionsValue.MaxAssociations = 8;
    const auto RelayTask = StartUdpRelay({ioc, a, b, RelayOptionsValue});

    Net::ip::udp::socket client_a(ioc.get_executor());
    Net::ip::udp::socket client_b(ioc.get_executor());
    Net::ip::udp::socket client_a2(ioc.get_executor());
    client_a.open(Net::ip::udp::v4(), oec);
    client_a.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_b.open(Net::ip::udp::v4(), oec);
    client_b.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    client_a2.open(Net::ip::udp::v4(), oec);
    client_a2.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), oec);
    ASSERT_FALSE(oec);

    RunCoro(ioc, RunOneSidedTrafficScenario(
        {{{a_ep, b_ep, a, RelayTask, client_a, client_b}, ioc, oec}, client_a2}));
}
