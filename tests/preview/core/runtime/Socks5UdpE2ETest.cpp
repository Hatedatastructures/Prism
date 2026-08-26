/**
 * @file Socks5UdpE2ETest.cpp
 * @brief SOCKS5 UDP ASSOCIATE 纵向链路测试（阶段 3 遗留：真实 UDP 数据面）
 * @details 与 TCP 链路共用 runtime Session 编排，验证 Dgram 分支：
 *          Client TCP 握手 UDP_ASSOCIATE → BND 端口 →
 *          Client UDP 帧 → UdpAssoc 解帧 → 上游 echo → 封帧回包。
 *          覆盖：多包往返、非法帧丢弃、空闲超时、TCP 控制断开终止。
 */

#include <gtest/gtest.h>

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
#include <common/Protocols/Socks5/Socks5.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using udp = net::ip::udp;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using Preview::Testing::RunCoro;
    using TrafficRecorder = Preview::Testing::TrafficRecorder;
    using Preview::Testing::UdpEchoServer;


    /// 构造 SOCKS5 服务端接入回调（UDP_ASSOCIATE → Dgram 会话标记）
    auto make_accept_socks5_udp() -> Runtime::SessionOptions::ProtocolAcceptFn
    {
        Socks5::ServerConfig cfg;
        cfg.EnableUdp = true;
        // UDP_ASSOCIATE 应答必须由数据面 Bind 后发送（携带 BND），
        // 不能使用握手默认的 0.0.0.0:0
        cfg.DeferConnectReply = true;
        return Runtime::MakeAcceptSocks5(std::move(cfg));
    }

    /// 构造 UDP 数据面服务（Bind → BND → 帧循环；目标由 resolve 决定）
    auto make_udp_service(
        std::function<net::awaitable<std::pair<Error, udp::endpoint>>(
            const Socks5::Address &)> resolve,
        std::chrono::milliseconds IdleTimeout)
        -> std::function<net::awaitable<Fault::Code>(Middleware::Context &)>
    {
        return [resolve = std::move(resolve), IdleTimeout](Middleware::Context &ctx)
            -> net::awaitable<Fault::Code>
        {
            auto Tcp = std::dynamic_pointer_cast<Socks5::Conn<>>(ctx.Inbound);
            if (!Tcp)
            {
                co_return Fault::Code::ProtocolError;
            }
            Socks5::UdpAssocOptions opts;
            opts.IdleTimeout = IdleTimeout;
            opts.resolve = std::move(resolve);
            // 流量统计：Session 已把 sink/identity 装配进 ctx，透传给数据面
            opts.traffic = ctx.traffic;
            opts.identity = ctx.identity;
            auto svc = std::make_shared<Socks5::UdpAssoc>(
                ctx.Inbound->Executor(), std::move(Tcp), std::move(opts));
            if (co_await svc->BindAndReply() != Error::None)
            {
                co_return Fault::Code::IoError;
            }
            co_await svc->Run();
            co_return Fault::Code::Success;
        };
    }

    /// 构造 UDP 数据面服务（目标固定重定向到 echo 端点）
    auto make_udp_service(std::uint16_t echo_port, std::chrono::milliseconds IdleTimeout)
        -> std::function<net::awaitable<Fault::Code>(Middleware::Context &)>
    {
        return make_udp_service(
            [echo_port](const Socks5::Address &)
                -> net::awaitable<std::pair<Error, udp::endpoint>>
            {
                co_return std::pair{Error::None,
                                    net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"),
                                                  echo_port)};
            },
            IdleTimeout);
    }

    /// 构造一个 SOCKS5 UDP 帧
    auto make_frame(const Socks5::Address &Target, std::string_view payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Frame;
        Socks5::BuildUdpDatagram(
            Target,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
            Frame);
        return Frame;
    }

    /// 客户端 UDP 收发一次（发帧 + 收帧 + 解析）
    struct udp_roundtrip_result
    {
        std::string echo;
        Socks5::Address src;
        bool Ok{false};
    };

    /// 客户端通过真实 UDP socket 与代理数据面往返一次
    auto udp_roundtrip(udp::socket &cudp, const udp::endpoint &bnd_ep,
                       const std::vector<std::uint8_t> &Frame)
        -> net::awaitable<udp_roundtrip_result>
    {
        udp_roundtrip_result out;
        boost::system::error_code ec;
        co_await cudp.async_send_to(net::buffer(Frame), bnd_ep,
                                    net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            co_return out;
        }
        std::array<std::byte, 65535> Rx{};
        udp::endpoint src_ep;
        // 看门狗竞速：数据面断裂时失败而非挂死
        net::steady_timer wd(cudp.get_executor());
        wd.expires_after(std::chrono::seconds(2));
        using boost::asio::experimental::awaitable_operators::operator||;
        auto Result = co_await (cudp.async_receive_from(
                                    net::buffer(Rx), src_ep,
                                    net::redirect_error(net::use_awaitable, ec)) ||
                                wd.async_wait(net::use_awaitable));
        if (Result.index() == 1 || ec)
        {
            co_return out;
        }
        const auto n = std::get<0>(std::move(Result));
        Socks5::Address src;
        std::span<const std::uint8_t> payload;
        if (Socks5::ParseUdpDatagram(
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

    TEST(TcpListener, Socks5UdpAssociateEcho)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(net::ip::udp::v4(), oec);
        echo_sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
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
                opts.AcceptProtocol = make_accept_socks5_udp();
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

                // TCP 握手 UDP_ASSOCIATE → BND
                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect(
                    "127.0.0.1", listen_port, ec);
                if (!raw)
                {
                    co_return;
                }
                auto [err, Conn] = co_await Socks5::Connect(
                    std::move(raw), Socks5::ClientConfig{},
                    Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
                    Socks5::Command::UdpAssociate);
                handshake_ok = err == Error::None && Conn != nullptr;
                if (!Conn)
                {
                    co_return;
                }
                const auto bnd = Conn->BindEndpoint();
                const udp::endpoint bnd_ep(net::ip::make_address(bnd.Host), bnd.Port);
                EXPECT_EQ(bnd.Type, Socks5::AddressType::Ipv4);

                // 客户端真实 UDP socket → 帧往返
                udp::socket cudp(ioc.get_executor());
                cudp.open(net::ip::udp::v4(), oec);
                cudp.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                const auto frame1 = make_frame(
                    Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
                    "udp payload one");
                const auto r1 = co_await udp_roundtrip(cudp, bnd_ep, frame1);
                echo1 = r1.echo;

                const auto frame2 = make_frame(
                    Socks5::Address{Socks5::AddressType::Ipv4, "8.8.8.8", 443},
                    "udp payload two");
                const auto r2 = co_await udp_roundtrip(cudp, bnd_ep, frame2);
                echo2 = r2.echo;

                cudp.close();
                Conn->Close();
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
        EXPECT_EQ(echo1, "udp payload one");
        EXPECT_EQ(echo2, "udp payload two");
        EXPECT_FALSE(*upstream_ep);
        // UDP 数据面流量必须经 traffic sink 上报（up/down 口径与 relay 一致）
        EXPECT_GT(recorder->Calls, 0);
        EXPECT_GT(recorder->Up, 0u);
        EXPECT_GT(recorder->Down, 0u);
    }

    TEST(TcpListener, Socks5UdpAssociateBadFrame)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(net::ip::udp::v4(), oec);
        echo_sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
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
                opts.AcceptProtocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        std::string echo_after_bad;
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
                auto [err, Conn] = co_await Socks5::Connect(
                    std::move(raw), Socks5::ClientConfig{},
                    Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
                    Socks5::Command::UdpAssociate);
                if (!Conn)
                {
                    co_return;
                }
                const auto bnd = Conn->BindEndpoint();
                const net::ip::udp::endpoint bnd_ep(net::ip::make_address(bnd.Host), bnd.Port);

                udp::socket cudp(ioc.get_executor());
                cudp.open(net::ip::udp::v4(), oec);
                cudp.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                // 非法帧：FRAG=1（不支持分片），应被丢弃且不中断关联
                std::vector<std::uint8_t> bad = {0x00, 0x00, 0x01, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x35, 'x'};
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(bad), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));

                // 合法帧仍可往返
                const auto Frame = make_frame(
                    Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
                    "after bad Frame");
                const auto r = co_await udp_roundtrip(cudp, bnd_ep, Frame);
                echo_after_bad = r.echo;

                cudp.close();
                Conn->Close();
                listener.Stop();
            });

        EXPECT_EQ(echo_after_bad, "after bad Frame");
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, Socks5UdpAssociateIdleTimeout)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(net::ip::udp::v4(), oec);
        echo_sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
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
                opts.AcceptProtocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::milliseconds(120));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool timeout_closed = false;
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
                auto [err, Conn] = co_await Socks5::Connect(
                    std::move(raw), Socks5::ClientConfig{},
                    Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
                    Socks5::Command::UdpAssociate);
                if (!Conn)
                {
                    co_return;
                }
                const auto bnd = Conn->BindEndpoint();
                const net::ip::udp::endpoint bnd_ep(net::ip::make_address(bnd.Host), bnd.Port);

                udp::socket cudp(ioc.get_executor());
                cudp.open(net::ip::udp::v4(), oec);
                cudp.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                // 空闲等待（超过服务端 IdleTimeout）
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::milliseconds(400));
                co_await t.async_wait(net::use_awaitable);

                // 超时后数据面已关闭：发包无回包（等待 300ms 判定）
                const auto Frame = make_frame(
                    Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
                    "too late");
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(Frame), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));

                std::array<std::byte, 512> Rx{};
                udp::endpoint src_ep;
                net::steady_timer Wait(ioc);
                Wait.expires_after(std::chrono::milliseconds(300));
                auto recv = cudp.async_receive_from(
                    net::buffer(Rx), src_ep, net::redirect_error(net::use_awaitable, sock_ec));
                auto wait_aw = Wait.async_wait(net::use_awaitable);
                using boost::asio::experimental::awaitable_operators::operator||;
                const auto res = co_await (std::move(recv) || std::move(wait_aw));
                // 数据面已关闭：无回包（超时）或端口关闭触发 ICMP 错误
                timeout_closed = res.index() == 1 ||
                                 sock_ec != boost::system::error_code{};

                cudp.close();
                Conn->Close();
                listener.Stop();
            });

        EXPECT_TRUE(timeout_closed);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, Socks5UdpAssociateTcpCloseTerminates)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(net::ip::udp::v4(), oec);
        echo_sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
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
                opts.AcceptProtocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool terminated = false;
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
                auto [err, Conn] = co_await Socks5::Connect(
                    std::move(raw), Socks5::ClientConfig{},
                    Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
                    Socks5::Command::UdpAssociate);
                if (!Conn)
                {
                    co_return;
                }
                const auto bnd = Conn->BindEndpoint();
                const net::ip::udp::endpoint bnd_ep(net::ip::make_address(bnd.Host), bnd.Port);

                // 先验证一次往返（数据面已建立）
                udp::socket cudp(ioc.get_executor());
                cudp.open(net::ip::udp::v4(), oec);
                cudp.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
                const auto Frame = make_frame(
                    Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
                    "first round");
                const auto r = co_await udp_roundtrip(cudp, bnd_ep, Frame);
                EXPECT_TRUE(r.Ok);

                // 关闭 TCP 控制连接 → 数据面应终止
                Conn->Close();
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::milliseconds(200));
                co_await t.async_wait(net::use_awaitable);

                // 再发包：无回包（等待 300ms 判定）
                const auto frame2 = make_frame(
                    Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
                    "after Tcp Close");
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(frame2), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));
                std::array<std::byte, 512> Rx{};
                udp::endpoint src_ep;
                net::steady_timer Wait(ioc);
                Wait.expires_after(std::chrono::milliseconds(300));
                auto recv = cudp.async_receive_from(
                    net::buffer(Rx), src_ep, net::redirect_error(net::use_awaitable, sock_ec));
                auto wait_aw = Wait.async_wait(net::use_awaitable);
                using boost::asio::experimental::awaitable_operators::operator||;
                const auto res = co_await (std::move(recv) || std::move(wait_aw));
                // 数据面已随 TCP 关闭终止：无回包（超时）或 ICMP 错误
                terminated = res.index() == 1 ||
                             sock_ec != boost::system::error_code{};

                cudp.close();
                listener.Stop();
            });

        EXPECT_TRUE(terminated);
        EXPECT_FALSE(*upstream_ep);
    }


    TEST(TcpListener, Socks5UdpAssociateSilentUpstreamIdleTimeout)
    {
        // 客户端发一个数据报到静默目标（无回包）：空闲超时也必须回收关联，
        // 不能因为等上游回包而无限挂住（A-1 回归）。
        net::io_context ioc;
        boost::system::error_code oec;
        const auto idle_to = std::chrono::milliseconds(120);

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(
                    [](const Socks5::Address &)
                        -> net::awaitable<std::pair<Error, udp::endpoint>>
                    {
                        // 黑洞端点：无监听者、无回包
                        co_return std::pair{Error::None,
                                            net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 1)};
                    },
                    idle_to);
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool closed_by_idle = false;
        bool watchdog_fired = false;
        net::steady_timer watchdog(ioc);
        watchdog.expires_after(std::chrono::seconds(5));
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                boost::system::error_code wec;
                co_await watchdog.async_wait(net::redirect_error(net::use_awaitable, wec));
                watchdog_fired = true;
                ioc.stop();
            },
            net::detached);

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
                    listener.Stop();
                    co_return;
                }
                auto [err, Conn] = co_await Socks5::Connect(
                    std::move(raw), Socks5::ClientConfig{},
                    Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", 0},
                    Socks5::Command::UdpAssociate);
                if (!Conn)
                {
                    listener.Stop();
                    co_return;
                }
                const auto bnd = Conn->BindEndpoint();
                const net::ip::udp::endpoint bnd_ep(net::ip::make_address(bnd.Host), bnd.Port);

                udp::socket cudp(ioc.get_executor());
                cudp.open(net::ip::udp::v4(), oec);
                cudp.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                // 发一个数据报到黑洞目标（无回包）
                const auto Frame = make_frame(
                    Socks5::Address{Socks5::AddressType::Domain, "example.com", 53},
                    "to silent Target");
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(Frame), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));

                // 等待超过 IdleTimeout：TCP 控制连接应被服务端关闭（EOF/错误）。
                // 注意：不能把 ec != {} 当作关闭信号——等待超时赢时取消读也会置
                // operation_aborted，会让「未关闭」误判为「已关闭」（vacuously pass）。
                std::array<std::byte, 1> Probe{};
                net::steady_timer Wait(ioc);
                Wait.expires_after(idle_to + std::chrono::milliseconds(400));
                auto rd = Conn->async_read_some(std::span(Probe), ec);
                auto wt = Wait.async_wait(net::use_awaitable);
                using boost::asio::experimental::awaitable_operators::operator||;
                const auto res = co_await (std::move(rd) || std::move(wt));
                closed_by_idle = res.index() == 0;

                cudp.close();
                Conn->Close();
                listener.Stop();
            });

        EXPECT_FALSE(watchdog_fired);
        EXPECT_TRUE(closed_by_idle);
    }
} // namespace
