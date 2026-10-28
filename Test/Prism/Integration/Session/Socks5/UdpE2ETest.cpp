#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file UdpE2ETest.cpp
 * @brief SOCKS5 UDP ASSOCIATE 纵向链路测试（阶段 3 遗留：真实 UDP 数据面）
 * @details 与 TCP 链路共用 runtime Session 编排，验证 Dgram 分支：
 *          Client TCP 握手 UDP_ASSOCIATE → BND 端口 →
 *          Client UDP 帧 → UdpAssoc 解帧 → 上游 echo → 封帧回包。
 *          覆盖：多包往返、非法帧丢弃、空闲超时、TCP 控制断开终止。
 */

#include <gtest/gtest.h>
#include <Prism/Contract/Services/Datagram.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include "UdpE2ETestSupport.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Middleware = Prism::Middleware;
    namespace Network = Prism::Network;
    namespace Runtime = Prism::Runtime;
    namespace Socks5 = Prism::Socks5;
    using Tcp = Net::ip::tcp;
    using Udp = Net::ip::udp;
    using Prism::Error;
    using Prism::SharedTransmission;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::RunCoro;
    using TrafficRecorder = Prism::Testing::TrafficRecorder;
    using Prism::Testing::UdpEchoServer;


    using Socks5UdpTestSupport::MakeFrame;
    using Socks5UdpTestSupport::RunUdpRoundtrip;
    using Socks5UdpTestSupport::Socks5UdpSessionFactory;
    using Socks5UdpTestSupport::RunSocks5UdpFamilyFlow;
    using Socks5UdpTestSupport::Socks5UdpFamilyFlow;
    using Socks5UdpTestSupport::RunSocks5UdpPeerFlow;
    using Socks5UdpTestSupport::Socks5UdpPeerFlow;
    using Socks5UdpTestSupport::SendSocks5UdpAssociateRequest;

    TEST(TcpListener, Socks5UdpAssociateRejectsNonControlPeer)
    {
        Net::io_context IoContext;
        Udp::socket EchoSocket(IoContext.get_executor());
        boost::system::error_code ErrorCode;
        EchoSocket.open(Udp::v4(), ErrorCode);
        EchoSocket.bind(Udp::endpoint(Net::ip::address_v4::loopback(), 0), ErrorCode);
        ASSERT_FALSE(ErrorCode);
        const auto EchoPort = EchoSocket.local_endpoint().port();
        auto UpstreamFailure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(IoContext.get_executor(), Prism::Testing::UdpEchoServer(std::move(EchoSocket)),
                      [UpstreamFailure](const std::exception_ptr &Failure)
                      {
                          if (Failure) *UpstreamFailure = Failure;
                      });
        auto Recorder = std::make_shared<Prism::Testing::TrafficRecorder>();
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = Socks5UdpSessionFactory{EchoPort, std::chrono::seconds(5), Recorder, {}},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});
        bool RogueAccepted = false;
        bool ControlAccepted = false;
        RunCoro(IoContext, RunSocks5UdpPeerFlow(
            Socks5UdpPeerFlow{IoContext, Listener, RogueAccepted, ControlAccepted}));
        EXPECT_FALSE(RogueAccepted);
        EXPECT_TRUE(ControlAccepted);
        EXPECT_FALSE(*UpstreamFailure);
        EXPECT_EQ(Recorder->Calls, 1);
    }

    struct Socks5UdpReplyFailureFlow final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        bool &RequestSent;
    };

    /** @brief 控制 TCP 在 deferred BND reply 前关闭时，association 仍须完成一次收口。 */
    auto RunSocks5UdpReplyFailureFlow(Socks5UdpReplyFailureFlow Flow)
        -> Net::awaitable<void>
    {
        co_await Flow.Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        if (!Dialed || !*Dialed)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Raw = std::move(*Dialed);
        Flow.RequestSent = co_await SendSocks5UdpAssociateRequest(Raw);
        (void)Raw->Cancel();
        (void)Raw->Close();
        Net::steady_timer Delay(Flow.Io.get_executor());
        Delay.expires_after(std::chrono::milliseconds(150));
        co_await Delay.async_wait(Net::use_awaitable);
        co_await Flow.Listener.Shutdown();
    }

    TEST(TcpListener, Socks5UdpAssociateReplyFailureFinalizesOnce)
    {
        Net::io_context IoContext;
        auto Recorder = std::make_shared<Prism::Testing::TrafficRecorder>();
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = Socks5UdpSessionFactory{0, std::chrono::seconds(5), Recorder, {}},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{2})});
        bool RequestSent = false;
        RunCoro(IoContext, RunSocks5UdpReplyFailureFlow(
            Socks5UdpReplyFailureFlow{IoContext, Listener, RequestSent}));
        EXPECT_TRUE(RequestSent);
        EXPECT_EQ(Recorder->Calls, 1);
    }
    struct Socks5UdpBadFrameFlow final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        std::string &EchoAfterBad;
    };

    /** @brief 验证 SOCKS5 非法 FRAG 帧丢弃后关联仍可用。 */
    auto RunSocks5UdpBadFrameFlow(Socks5UdpBadFrameFlow Flow)
        -> Net::awaitable<void>
    {
        co_await Flow.Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto ListenPort = Flow.Listener.LocalEndpoint().port();
        Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (!Dialed || !*Dialed)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Raw = std::move(*Dialed);
        auto ConnectResult = co_await Socks5::Connect({
            std::move(Raw), Socks5::ClientConfig{},
            Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
            Socks5::Command::UdpAssociate});
        if (!ConnectResult || !*ConnectResult)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Connection = std::move(*ConnectResult);
        const auto Bind = Connection->BindEndpoint();
        const Udp::endpoint BindEndpoint(
            Net::ip::make_address(Bind.Host), Bind.Port);
        Udp::socket ClientSocket(Flow.Io.get_executor());
        boost::system::error_code SocketError;
        ClientSocket.open(Net::ip::udp::v4(), SocketError);
        ClientSocket.bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), SocketError);
        const std::vector<std::uint8_t> BadFrame{
            0x00, 0x00, 0x01, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x35, 'x'};
        co_await ClientSocket.async_send_to(
            Net::buffer(BadFrame), BindEndpoint,
            Net::redirect_error(Net::use_awaitable, SocketError));
        const auto Frame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
            "after bad Frame");
        const auto Result = co_await RunUdpRoundtrip(
            ClientSocket, BindEndpoint, Frame);
        Flow.EchoAfterBad = Result.Echo;
        ClientSocket.close();
        (void)Connection->Close();
        co_await Flow.Listener.Shutdown();
    }

    struct Socks5UdpIdleFlow final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        bool &Closed;
    };

    /** @brief 驱动 SOCKS5 UDP 关联空闲超时后的真实关闭。 */
    auto RunSocks5UdpIdleFlow(Socks5UdpIdleFlow Flow) -> Net::awaitable<void>
    {
        co_await Flow.Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto ListenPort = Flow.Listener.LocalEndpoint().port();
        Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (!Dialed || !*Dialed)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Raw = std::move(*Dialed);
        auto ConnectResult = co_await Socks5::Connect({
            std::move(Raw), Socks5::ClientConfig{},
            Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
            Socks5::Command::UdpAssociate});
        if (!ConnectResult || !*ConnectResult)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Connection = std::move(*ConnectResult);
        const auto Bind = Connection->BindEndpoint();
        const Udp::endpoint BindEndpoint(
            Net::ip::make_address(Bind.Host), Bind.Port);
        Udp::socket ClientSocket(Flow.Io.get_executor());
        boost::system::error_code SocketError;
        ClientSocket.open(Net::ip::udp::v4(), SocketError);
        ClientSocket.bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), SocketError);
        Net::steady_timer Idle(Flow.Io.get_executor());
        Idle.expires_after(std::chrono::milliseconds(400));
        co_await Idle.async_wait(Net::use_awaitable);
        const auto Frame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
            "too late");
        co_await ClientSocket.async_send_to(
            Net::buffer(Frame), BindEndpoint,
            Net::redirect_error(Net::use_awaitable, SocketError));
        std::array<std::byte, 512> Buffer{};
        Udp::endpoint Source;
        Net::steady_timer Wait(Flow.Io.get_executor());
        Wait.expires_after(std::chrono::milliseconds(300));
        auto Receive = ClientSocket.async_receive_from(
            Net::buffer(Buffer), Source,
            Net::redirect_error(Net::use_awaitable, SocketError));
        auto WaitOperation = Wait.async_wait(Net::use_awaitable);
        const auto Result = co_await Net::experimental::awaitable_operators::operator||(
            std::move(Receive), std::move(WaitOperation));
        Flow.Closed = Result.index() == 1 ||
                      SocketError != boost::system::error_code{};
        ClientSocket.close();
        (void)Connection->Close();
        co_await Flow.Listener.Shutdown();
    }

    struct Socks5UdpTcpCloseFlow final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        bool &Terminated;
    };

    /** @brief 驱动 SOCKS5 UDP 控制 TCP 关闭后的数据面退出。 */
    auto RunSocks5UdpTcpCloseFlow(Socks5UdpTcpCloseFlow Flow)
        -> Net::awaitable<void>
    {
        co_await Flow.Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto ListenPort = Flow.Listener.LocalEndpoint().port();
        Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (!Dialed || !*Dialed)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Raw = std::move(*Dialed);
        auto ConnectResult = co_await Socks5::Connect({
            std::move(Raw), Socks5::ClientConfig{},
            Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
            Socks5::Command::UdpAssociate});
        if (!ConnectResult || !*ConnectResult)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Connection = std::move(*ConnectResult);
        const auto Bind = Connection->BindEndpoint();
        const Udp::endpoint BindEndpoint(
            Net::ip::make_address(Bind.Host), Bind.Port);
        Udp::socket ClientSocket(Flow.Io.get_executor());
        boost::system::error_code SocketError;
        ClientSocket.open(Net::ip::udp::v4(), SocketError);
        ClientSocket.bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), SocketError);
        const auto FirstFrame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
            "first round");
        const auto FirstResult = co_await RunUdpRoundtrip(
            ClientSocket, BindEndpoint, FirstFrame);
        EXPECT_TRUE(FirstResult.Ok);
        (void)Connection->Close();
        Net::steady_timer CloseDelay(Flow.Io.get_executor());
        CloseDelay.expires_after(std::chrono::milliseconds(200));
        co_await CloseDelay.async_wait(Net::use_awaitable);
        const auto SecondFrame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
            "after Tcp Close");
        co_await ClientSocket.async_send_to(
            Net::buffer(SecondFrame), BindEndpoint,
            Net::redirect_error(Net::use_awaitable, SocketError));
        std::array<std::byte, 512> Buffer{};
        Udp::endpoint Source;
        Net::steady_timer Wait(Flow.Io.get_executor());
        Wait.expires_after(std::chrono::milliseconds(300));
        auto Receive = ClientSocket.async_receive_from(
            Net::buffer(Buffer), Source,
            Net::redirect_error(Net::use_awaitable, SocketError));
        auto WaitOperation = Wait.async_wait(Net::use_awaitable);
        const auto Result = co_await Net::experimental::awaitable_operators::operator||(
            std::move(Receive), std::move(WaitOperation));
        Flow.Terminated = Result.index() == 1 ||
                          SocketError != boost::system::error_code{};
        ClientSocket.close();
        co_await Flow.Listener.Shutdown();
    }

    struct Socks5UdpSilentWatchdogState;

    struct Socks5UdpSilentFlow final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        std::chrono::milliseconds IdleTimeout;
        bool &ClosedByIdle;
        bool &WatchdogFired;
        const std::shared_ptr<Socks5UdpSilentWatchdogState> &Watchdog;
    };

    struct Socks5UdpSilentWatchdogState final
    {
        Runtime::TcpListener *Listener;
        std::shared_ptr<Net::steady_timer> Timer;
        std::shared_ptr<SharedTransmission> Connection;
        bool *Fired;
    };

    auto RunSocks5UdpSilentWatchdog(
        const std::shared_ptr<Socks5UdpSilentWatchdogState> &State)
        -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await State->Timer->async_wait(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return;
        }
        *State->Fired = true;
        if (State->Connection && *State->Connection)
        {
            (void)(*State->Connection)->Close();
        }
        State->Listener->Stop();
    }

    /** @brief 驱动静默上游并验证 UDP idle timeout 不会永久等待。 */
    auto RunSocks5UdpSilentFlow(Socks5UdpSilentFlow Flow)
        -> Net::awaitable<void>
    {
        co_await Flow.Listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto ListenPort = Flow.Listener.LocalEndpoint().port();
        Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
        if (!Dialed || !*Dialed)
        {
            Flow.Watchdog->Timer->cancel();
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Raw = std::move(*Dialed);
        *Flow.Watchdog->Connection = Raw;
        auto ConnectResult = co_await Socks5::Connect({
            std::move(Raw), Socks5::ClientConfig{},
            Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
            Socks5::Command::UdpAssociate});
        if (!ConnectResult || !*ConnectResult)
        {
            Flow.Watchdog->Timer->cancel();
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto Connection = std::move(*ConnectResult);
        *Flow.Watchdog->Connection = Connection;
        const auto Bind = Connection->BindEndpoint();
        const Udp::endpoint BindEndpoint(
            Net::ip::make_address(Bind.Host), Bind.Port);
        Udp::socket ClientSocket(Flow.Io.get_executor());
        boost::system::error_code SocketError;
        ClientSocket.open(Net::ip::udp::v4(), SocketError);
        ClientSocket.bind(
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), SocketError);
        const auto Frame = MakeFrame(
            Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
            "to silent Target");
        co_await ClientSocket.async_send_to(
            Net::buffer(Frame), BindEndpoint,
            Net::redirect_error(Net::use_awaitable, SocketError));
        std::array<std::byte, 1> Probe{};
        Net::steady_timer Wait(Flow.Io.get_executor());
        Wait.expires_after(Flow.IdleTimeout + std::chrono::milliseconds(400));
        std::error_code ReadError;
        auto Read = Connection->ReadSome(std::span(Probe));
        auto WaitOperation = Wait.async_wait(Net::use_awaitable);
        const auto Result = co_await Net::experimental::awaitable_operators::operator||(
            std::move(Read), std::move(WaitOperation));
        if (Result.index() == 0)
        {
            ReadError = Prism::Fault::ToNative(std::get<0>(Result).Failure);
        }
        Flow.ClosedByIdle = Result.index() == 0;
        Flow.Watchdog->Timer->cancel();
        Flow.Watchdog->Connection->reset();
        Flow.WatchdogFired = *Flow.Watchdog->Fired;
        ClientSocket.close();
        (void)Connection->Close();
        co_await Flow.Listener.Shutdown();
    }

    TEST(TcpListener, Socks5UdpAssociateEcho)
    {
        Net::io_context IoContext;
        auto Recorder = std::make_shared<Prism::Testing::TrafficRecorder>();
        std::string FirstEcho;
        std::string SecondEcho;
        bool HandshakeSucceeded = false;
        RunCoro(IoContext, RunSocks5UdpFamilyFlow(Socks5UdpFamilyFlow{
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            "127.0.0.1", Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Socks5::AddressType::Ipv4, "127.0.0.1", Recorder,
            FirstEcho, SecondEcho, HandshakeSucceeded}));

        EXPECT_TRUE(HandshakeSucceeded);
        EXPECT_EQ(FirstEcho, "udp payload one");
        EXPECT_EQ(SecondEcho, "udp payload two");
        // UDP 数据面流量必须经 traffic sink 上报（up/down 口径与 relay 一致）
        EXPECT_GT(Recorder->Calls, 0);
        EXPECT_EQ(Recorder->Calls, 1);
        EXPECT_GT(Recorder->Up, 0u);
        EXPECT_GT(Recorder->Down, 0u);
    }

    TEST(TcpListener, Socks5UdpAssociateRemoteBindAddress)
    {
        Net::io_context IoContext;
        auto Recorder = std::make_shared<Prism::Testing::TrafficRecorder>();
        std::string FirstEcho;
        std::string SecondEcho;
        bool HandshakeSucceeded = false;
        RunCoro(IoContext, RunSocks5UdpFamilyFlow(Socks5UdpFamilyFlow{
            IoContext, Tcp::endpoint(Net::ip::make_address("127.0.0.2"), 0), "127.0.0.2",
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Udp::endpoint(Net::ip::make_address("127.0.0.1"), 0),
            Socks5::AddressType::Ipv4, "127.0.0.2", Recorder, FirstEcho, SecondEcho,
            HandshakeSucceeded}));
        EXPECT_TRUE(HandshakeSucceeded);
        EXPECT_EQ(FirstEcho, "udp payload one");
        EXPECT_EQ(SecondEcho, "udp payload two");
        EXPECT_EQ(Recorder->Calls, 1);
    }

    TEST(TcpListener, Socks5UdpAssociateIpv6Family)
    {
        Net::io_context IoContext;
        auto Recorder = std::make_shared<Prism::Testing::TrafficRecorder>();
        std::string FirstEcho;
        std::string SecondEcho;
        bool HandshakeSucceeded = false;
        RunCoro(IoContext, RunSocks5UdpFamilyFlow(Socks5UdpFamilyFlow{
            IoContext, Tcp::endpoint(Net::ip::make_address("::1"), 0), "::1",
            Udp::endpoint(Net::ip::make_address("::1"), 0),
            Udp::endpoint(Net::ip::make_address("::1"), 0),
            Socks5::AddressType::Ipv6, "::1", Recorder, FirstEcho, SecondEcho,
            HandshakeSucceeded}));
        EXPECT_TRUE(HandshakeSucceeded);
        EXPECT_EQ(FirstEcho, "udp payload one");
        EXPECT_EQ(SecondEcho, "udp payload two");
        EXPECT_EQ(Recorder->Calls, 1);
    }

    TEST(TcpListener, Socks5UdpAssociateBadFrame)
    {
        Net::io_context IoContext;
        Udp::socket EchoSocket(IoContext.get_executor());
        boost::system::error_code OpenErrorCode;
        EchoSocket.open(Net::ip::udp::v4(), OpenErrorCode);
        EchoSocket.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), OpenErrorCode);
        ASSERT_FALSE(OpenErrorCode);
        const auto EchoPort = EchoSocket.local_endpoint().port();
        auto UpstreamEndpoint = std::make_shared<std::exception_ptr>();
        auto Endpoint = UpstreamEndpoint;
        Net::co_spawn(IoContext.get_executor(), Prism::Testing::UdpEchoServer(std::move(EchoSocket)),
                      [Endpoint](const std::exception_ptr &Exception)
                      {
                          if (Exception)
                          {
                              *Endpoint = Exception;
                          }
                      });

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = Socks5UdpSessionFactory{
                EchoPort, std::chrono::seconds(5), {}, {}},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{3})});

        std::string EchoAfterBadRequest;
        RunCoro(IoContext, RunSocks5UdpBadFrameFlow(
            Socks5UdpBadFrameFlow{IoContext, Listener, EchoAfterBadRequest}));

        EXPECT_EQ(EchoAfterBadRequest, "after bad Frame");
        EXPECT_FALSE(*UpstreamEndpoint);
    }

    TEST(TcpListener, Socks5UdpAssociateIdleTimeout)
    {
        Net::io_context IoContext;
        Udp::socket EchoSocket(IoContext.get_executor());
        boost::system::error_code OpenErrorCode;
        EchoSocket.open(Net::ip::udp::v4(), OpenErrorCode);
        EchoSocket.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), OpenErrorCode);
        ASSERT_FALSE(OpenErrorCode);
        const auto EchoPort = EchoSocket.local_endpoint().port();
        auto UpstreamEndpoint = std::make_shared<std::exception_ptr>();
        auto Endpoint = UpstreamEndpoint;
        Net::co_spawn(IoContext.get_executor(), Prism::Testing::UdpEchoServer(std::move(EchoSocket)),
                      [Endpoint](const std::exception_ptr &Exception)
                      {
                          if (Exception)
                          {
                              *Endpoint = Exception;
                          }
                      });

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = Socks5UdpSessionFactory{
                EchoPort, std::chrono::milliseconds(120), {}, {}},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{4})});

        bool TimeoutClosed = false;
        RunCoro(IoContext, RunSocks5UdpIdleFlow(
            Socks5UdpIdleFlow{IoContext, Listener, TimeoutClosed}));

        EXPECT_TRUE(TimeoutClosed);
        EXPECT_FALSE(*UpstreamEndpoint);
    }

    TEST(TcpListener, Socks5UdpAssociateTcpCloseTerminates)
    {
        Net::io_context IoContext;
        Udp::socket EchoSocket(IoContext.get_executor());
        boost::system::error_code OpenErrorCode;
        EchoSocket.open(Net::ip::udp::v4(), OpenErrorCode);
        EchoSocket.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), OpenErrorCode);
        ASSERT_FALSE(OpenErrorCode);
        const auto EchoPort = EchoSocket.local_endpoint().port();
        auto UpstreamEndpoint = std::make_shared<std::exception_ptr>();
        auto Endpoint = UpstreamEndpoint;
        Net::co_spawn(IoContext.get_executor(), Prism::Testing::UdpEchoServer(std::move(EchoSocket)),
                      [Endpoint](const std::exception_ptr &Exception)
                      {
                          if (Exception)
                          {
                              *Endpoint = Exception;
                          }
                      });

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = Socks5UdpSessionFactory{
                EchoPort, std::chrono::seconds(5), {}, {}},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{5})});

        bool Terminated = false;
        RunCoro(IoContext, RunSocks5UdpTcpCloseFlow(
            Socks5UdpTcpCloseFlow{IoContext, Listener, Terminated}));

        EXPECT_TRUE(Terminated);
        EXPECT_FALSE(*UpstreamEndpoint);
    }


    TEST(TcpListener, Socks5UdpAssociateSilentUpstreamIdleTimeout)
    {
        // 客户端发一个数据报到静默目标（无回包）：空闲超时也必须回收关联，
        // 不能因为等上游回包而无限挂住（A-1 回归）。
        Net::io_context IoContext;
        boost::system::error_code OpenErrorCode;
        const auto IdleTimeout = std::chrono::milliseconds(120);

        const auto SilentResolver = [](Prism::Network::Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Prism::Fault::Failure>>
        {
            co_return Udp::endpoint(Net::ip::address_v4::loopback(), 1);
        };

        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
            .Executor = IoContext.get_executor(),
            .Factory = Socks5UdpSessionFactory{0, IdleTimeout, {}, SilentResolver},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{6})});

        bool ClosedByIdle = false;
        bool WatchdogFired = false;
        auto WatchdogFailure = std::make_shared<std::exception_ptr>();
        auto WatchdogState = std::make_shared<Socks5UdpSilentWatchdogState>(
            Socks5UdpSilentWatchdogState{
                &Listener,
                std::make_shared<Net::steady_timer>(IoContext),
                std::make_shared<SharedTransmission>(),
                &WatchdogFired});
        WatchdogState->Timer->expires_after(std::chrono::seconds(5));
        Net::co_spawn(
            IoContext.get_executor(),
            RunSocks5UdpSilentWatchdog(WatchdogState),
            [WatchdogFailure](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue && !*WatchdogFailure)
                {
                    *WatchdogFailure = ErrorValue;
                }
            });

        RunCoro(IoContext, RunSocks5UdpSilentFlow(Socks5UdpSilentFlow{
            IoContext, Listener, IdleTimeout, ClosedByIdle, WatchdogFired, WatchdogState}));

        EXPECT_FALSE(*WatchdogFailure);
        EXPECT_FALSE(WatchdogFired);
        EXPECT_TRUE(ClosedByIdle);
    }

    TEST(Socks5UdpAssociation, PendingBindIsSharedWithRunAndConcurrentCaller)
    {
        Net::io_context IoContext;
        auto Flow = std::make_shared<Socks5UdpTestSupport::BindGateRaceState>(IoContext);
        RunCoro(IoContext, Socks5UdpTestSupport::RunBindGateRace(IoContext, Flow));

        EXPECT_FALSE(Flow->WriteStartTimedOut);
        EXPECT_TRUE(Flow->RunWaited);
        EXPECT_TRUE(Flow->SecondWaited);
        ASSERT_TRUE(Flow->First);
        ASSERT_TRUE(Flow->Second);
        EXPECT_EQ(*Flow->First, *Flow->Second);
        EXPECT_EQ(*Flow->First, 10U);
        EXPECT_EQ(Flow->ReadBytes, 10U);
        EXPECT_EQ(Flow->WrittenBytes, 10U);
        EXPECT_EQ(Flow->Wire[0], std::byte{Socks5::Version});
        EXPECT_EQ(Flow->Wire[1],
                  std::byte{static_cast<std::uint8_t>(Socks5::ReplyCode::Success)});
        EXPECT_TRUE(Flow->RunResult.has_value());
        EXPECT_TRUE(Flow->ClientCloseAccepted);
        EXPECT_TRUE(Flow->ClientDrain);
        EXPECT_TRUE(Flow->AssociationDrain);
    }

    TEST(Socks5UdpAssociation, CancelingOneBindWaiterPreservesSharedOperation)
    {
        Net::io_context IoContext;
        auto Flow = std::make_shared<Socks5UdpTestSupport::BindGateRaceState>(IoContext);
        RunCoro(IoContext, Socks5UdpTestSupport::RunBindGateCancellation(IoContext, Flow));

        EXPECT_FALSE(Flow->WriteStartTimedOut);
        EXPECT_TRUE(Flow->SecondWaited);
        EXPECT_TRUE(Flow->SecondCanceled);
        EXPECT_TRUE(Flow->FirstPendingAfterWaiterCancel);
        ASSERT_FALSE(Flow->Second);
        EXPECT_EQ(Flow->Second.error().Transport.Code, Fault::Code::Canceled);
        EXPECT_EQ(Flow->Second.error().Transport.Native,
                  static_cast<std::error_code>(
                      Net::error::make_error_code(Net::error::operation_aborted)));
        ASSERT_TRUE(Flow->First);
        EXPECT_EQ(*Flow->First, 10U);
        EXPECT_EQ(Flow->ReadBytes, 10U);
        EXPECT_EQ(Flow->WrittenBytes, 10U);
        EXPECT_EQ(Flow->Wire[1],
                  std::byte{static_cast<std::uint8_t>(Socks5::ReplyCode::Success)});
        EXPECT_TRUE(Flow->ClientDrain);
        EXPECT_TRUE(Flow->AssociationDrain);
    }
} // namespace
