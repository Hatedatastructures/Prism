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
#include <vector>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Runtime/Adapter/ProtocolAdapter.hpp>
#include <common/Core/Runtime/Listener.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Vless/Vless.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;
    using Tcp = net::ip::tcp;
    using udp = net::ip::udp;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
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

    /// 构造一个 VLESS UDP 帧
    auto make_frame(const Vless::Address &Target, std::string_view payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Frame;
        Vless::BuildUdpPkt(
            Target,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
            Frame);
        return Frame;
    }

    /// 客户端流上往返一次：写帧 → 读回帧 → 解析
    struct roundtrip_result
    {
        std::string echo;
        Vless::Address src;
        bool Ok{false};
    };

    /// 客户端通过协议连接（流）发送一帧并接收回帧
    auto stream_roundtrip(const std::shared_ptr<Vless::Conn<>> &proxy,
                          const std::vector<std::uint8_t> &Frame)
        -> net::awaitable<roundtrip_result>
    {
        roundtrip_result out;
        std::error_code ec;
        std::size_t Done = 0;
        auto frame_span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Frame.data()), Frame.size());
        while (Done < Frame.size())
        {
            const auto written = co_await proxy->async_write_some(
                frame_span.subspan(Done), ec);
            if (ec)
            {
                co_return out;
            }
            Done += written;
        }
        std::array<std::byte, 65535> Rx{};
        std::error_code rec;
        // 看门狗竞速：数据面断裂时失败而非挂死（对齐 helpers 头范式）
        net::steady_timer wd(proxy->Executor());
        wd.expires_after(std::chrono::seconds(2));
        auto Result = co_await (proxy->async_read_some(std::span(Rx), rec) ||
                                wd.async_wait(net::use_awaitable));
        if (Result.index() == 1 || rec)
        {
            co_return out;
        }
        const auto n = std::get<0>(std::move(Result));
        if (n == 0)
        {
            co_return out;
        }
        Vless::Address src;
        std::span<const std::uint8_t> payload;
        if (Vless::ParseUdpPkt(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Rx.data()), n),
                src, payload) != Error::None)
        {
            co_return out;
        }
        out.echo.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
        out.src = std::move(src);
        out.Ok = true;
        co_return out;
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

        std::string echo1;
        std::string echo2;
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
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 0},
                    Vless::Command::Udp);
                handshake_ok = err == Error::None && proxy != nullptr;
                if (!proxy)
                {
                    co_return;
                }

                const auto frame1 = make_frame(
                    Vless::Address{Vless::AddressType::Domain, "example.com", 53},
                    "vless udp one");
                const auto r1 = co_await stream_roundtrip(proxy, frame1);
                echo1 = r1.echo;

                const auto frame2 = make_frame(
                    Vless::Address{Vless::AddressType::Ipv4, "8.8.8.8", 443},
                    "vless udp two");
                const auto r2 = co_await stream_roundtrip(proxy, frame2);
                echo2 = r2.echo;

                proxy->Close();
                // 有界轮询等数据面退出并上报流量（对齐 TrojanTrafficIdentity 样板）
                net::steady_timer timer(ioc);
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                while (recorder->Calls == 0 &&
                       std::chrono::steady_clock::now() < deadline)
                {
                    timer.expires_after(std::chrono::milliseconds(5));
                    co_await timer.async_wait(net::use_awaitable);
                }
                listener.Stop();
            });

        EXPECT_TRUE(handshake_ok);
        EXPECT_EQ(echo1, "vless udp one");
        EXPECT_EQ(echo2, "vless udp two");
        EXPECT_FALSE(*upstream_ep);
        // UDP 数据面流量必须经 traffic sink 上报（up/down 口径与 relay 一致）
        EXPECT_GT(recorder->Calls, 0);
        EXPECT_GT(recorder->Up, 0u);
        EXPECT_GT(recorder->Down, 0u);
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
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 0},
                    Vless::Command::Udp);
                if (!proxy)
                {
                    co_return;
                }
                // 空闲等待（超过服务端 IdleTimeout）→ 流被关闭
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::milliseconds(400));
                co_await t.async_wait(net::use_awaitable);

                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(std::span(buf), ec);
                closed = (n == 0 || ec != std::error_code{});

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

        bool first_ok = false;
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
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", 0},
                    Vless::Command::Udp);
                if (!proxy)
                {
                    co_return;
                }
                // 先验证一次往返（数据面已建立）
                const auto Frame = make_frame(
                    Vless::Address{Vless::AddressType::Domain, "example.com", 53},
                    "first round");
                const auto r = co_await stream_roundtrip(proxy, Frame);
                first_ok = r.Ok;

                // 关闭流（客户端断开）→ 数据面随 EOF 终止，无需再验证回包
                proxy->Close();
                listener.Stop();
            });

        EXPECT_TRUE(first_ok);
        EXPECT_FALSE(*upstream_ep);
    }

} // namespace
