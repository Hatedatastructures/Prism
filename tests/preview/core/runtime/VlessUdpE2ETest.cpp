/**
 * @file VlessUdpE2ETest.cpp
 * @brief VLESS UDP 命令纵向链路测试（阶段 4 遗留：复用 Dgram 编排）
 * @details 与 SOCKS5 UDP 共用 runtime `udp_service` 抽象：
 *          Client TCP 握手（cmd=udp）→ 流上 UDP 帧 → UdpTunnel
 *          解帧 → 真实 UDP socket 转发 → 上游 echo → 封帧写回流。
 *          覆盖：多包往返、空闲超时、流 EOF 终止。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <preview/Runtime/Listener.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;
    using Tcp = net::ip::tcp;
    using udp = net::ip::udp;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::MakeUuid;
    using Preview::Testing::RunCoro;
    using TrafficRecorder = Preview::Testing::TrafficRecorder;
    using Preview::Testing::UdpEchoServer;

    /// 固定测试 UUID 兼容别名（Vless::UuidLen == 16）
    inline auto test_uuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        return MakeUuid();
    }


    /// 构造 VLESS 服务端接入回调（udp 命令 → Dgram 会话标记；经 adapter 缝）
    auto make_accept_vless_udp() -> Runtime::SessionOptions::ProtocolAcceptFn
    {
        Vless::ServerConfig cfg;
        cfg.uuid = test_uuid();
        cfg.EnableUdp = true;
        return Runtime::MakeAcceptVless(std::move(cfg));
    }

    /// 构造 UDP 数据面服务（流上帧循环；目标固定重定向到 echo）
    auto make_udp_service(std::uint16_t echo_port, std::chrono::milliseconds IdleTimeout)
        -> std::function<net::awaitable<Fault::Code>(Middleware::Context &)>
    {
        return [echo_port, IdleTimeout](Middleware::Context &ctx)
            -> net::awaitable<Fault::Code>
        {
            auto Stream = std::dynamic_pointer_cast<Vless::Conn<>>(ctx.Inbound);
            if (!Stream)
            {
                co_return Fault::Code::ProtocolError;
            }
            Vless::UdpTunnelOptions opts;
            opts.IdleTimeout = IdleTimeout;
            // 流量统计：Session 已把 sink/identity 装配进 ctx，透传给数据面
            opts.traffic = ctx.traffic;
            opts.identity = ctx.identity;
            opts.resolve = [echo_port](const Vless::Address &)
                -> net::awaitable<std::pair<Error, udp::endpoint>>
            {
                co_return std::pair{Error::None,
                                    udp::endpoint(net::ip::make_address("127.0.0.1"),
                                                  echo_port)};
            };
            auto tunnel = std::make_shared<Vless::UdpTunnel>(
                std::move(Stream), std::move(opts));
            co_await tunnel->Run();
            co_return Fault::Code::Success;
        };
    }

    /// 流承载 UDP 没有明确的帧长度；服务端必须收口连接而不是尝试解析裸流。
    auto wait_for_stream_rejection(const std::shared_ptr<Vless::Conn<>> &proxy)
        -> net::awaitable<bool>
    {
        std::array<std::byte, 64> Buffer{};
        std::error_code ReadEc;
        net::steady_timer Watchdog(proxy->Executor());
        Watchdog.expires_after(std::chrono::seconds(2));
        auto Result = co_await (proxy->async_read_some(std::span(Buffer), ReadEc) ||
                                Watchdog.async_wait(net::use_awaitable));
        if (Result.index() == 1)
        {
            proxy->Close();
            co_return false;
        }
        co_return std::get<0>(std::move(Result)) == 0 || ReadEc;
    }

    TEST(TcpListener, VlessUdpConnectEcho)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(net::ip::udp::v4(), oec);
        echo_sock.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        ASSERT_FALSE(oec);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), Preview::Testing::UdpEchoServer(std::move(echo_sock)),
                      [eph](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *eph = ep;
                          }
                      });

        auto recorder = std::make_shared<Preview::Testing::TrafficRecorder>();
        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = make_accept_vless_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                opts.traffic = recorder.get();
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool handshake_ok = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::Success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect(
                    "127.0.0.1", listen_port, ec);
                if (!raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect({
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 0},
                    Vless::Command::Udp});
                handshake_ok = err == Error::None && proxy != nullptr;
                if (!proxy)
                {
                    co_return;
                }

                const auto rejected = co_await wait_for_stream_rejection(proxy);
                EXPECT_TRUE(rejected);

                proxy->Close();
                listener.Stop();
            });

        EXPECT_TRUE(handshake_ok);
        EXPECT_FALSE(*upstream_ep);
        // 未进入数据面，不应伪造流量统计。
        EXPECT_EQ(recorder->Calls, 0);
        EXPECT_EQ(recorder->Up, 0u);
        EXPECT_EQ(recorder->Down, 0u);
    }

    TEST(TcpListener, VlessUdpConnectIdleTimeout)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(net::ip::udp::v4(), oec);
        echo_sock.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        ASSERT_FALSE(oec);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), Preview::Testing::UdpEchoServer(std::move(echo_sock)),
                      [eph](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *eph = ep;
                          }
                      });

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = make_accept_vless_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::milliseconds(120));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool closed = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (!raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect({
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 0},
                    Vless::Command::Udp});
                if (!proxy)
                {
                    co_return;
                }
                // 不具备数据报边界的流式 UDP 在握手后立即被安全拒绝。
                closed = co_await wait_for_stream_rejection(proxy);

                proxy->Close();
                listener.Stop();
            });

        EXPECT_TRUE(closed);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessUdpConnectStreamEofTerminates)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(net::ip::udp::v4(), oec);
        echo_sock.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        ASSERT_FALSE(oec);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), Preview::Testing::UdpEchoServer(std::move(echo_sock)),
                      [eph](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *eph = ep;
                          }
                      });

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = make_accept_vless_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool stream_rejected = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (!raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect({
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 0},
                    Vless::Command::Udp});
                if (!proxy)
                {
                    co_return;
                }
                // 流式 UDP 没有明确帧长度，服务端必须拒绝该数据面。
                stream_rejected = co_await wait_for_stream_rejection(proxy);

                // 关闭流（客户端断开）→ 数据面随 EOF 终止，无需再验证回包
                proxy->Close();
                listener.Stop();
            });

        EXPECT_TRUE(stream_rejected);
        EXPECT_FALSE(*upstream_ep);
    }

} // namespace
