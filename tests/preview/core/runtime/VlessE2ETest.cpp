/**
 * @file VlessE2ETest.cpp
 * @brief VLESS 第二条纵向链路测试（阶段 4：抽象复用验证）
 * @details 与 SOCKS5 共用同一套 runtime Session 编排：
 *          listener → recognition → AcceptProtocol(vless) →
 *          Dial Middleware → relay Middleware → echo 上游。
 *          验证点：runtime 零协议特判（不复制 SOCKS5 的
 *          Accept/PostDial 编排），VLESS 仅提供握手与数据面。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Runtime/Adapter/ProtocolAdapter.hpp>
#include <common/Core/Runtime/Listener.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Transport/Reliable.hpp>
#include <common/Protocols/Vless/Vless.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游/tail_read_guarded 等见 <common/RuntimeTestHelpers.hpp>）
    using Preview::Testing::AcceptAndClose;
    using Preview::Testing::AcceptEchoLoop;
    using Preview::Testing::ChainState;
    
    using ConnectResult = Preview::Testing::ConnectResult;
    using Preview::Testing::MakeUuid;
    using Preview::Testing::RunCoro;
    using Preview::Testing::TailReadGuarded;
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::ToHex;
    using TrafficRecorder = Preview::Testing::TrafficRecorder;

    /// VLESS 纵向测试共享状态（复用公共 Preview::Testing::ChainState）
    using vless_chain_state = Preview::Testing::ChainState;

    /// 固定测试 UUID 兼容别名（Vless::UuidLen == 16）
    inline auto test_uuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        return MakeUuid();
    }

    /// 构造 VLESS 服务端接入回调（UUID 校验在握手内完成，无延迟应答；经 adapter 缝）
    auto MakeAcceptVless(Vless::ServerConfig cfg = {})
        -> Runtime::SessionOptions::ProtocolAcceptFn
    {
        return Runtime::MakeAcceptVless(std::move(cfg));
    }

    /// 连接 VLESS 纵向测试的回环上游（复用公共 DialUpstream）
    auto dial_vless_upstream(
        const std::shared_ptr<vless_chain_state> &State,
        const Network::Target &Target)
        -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        co_return co_await Preview::Testing::DialUpstream(State, Target);
    }

    /// 通用 VLESS TCP 真实链路运行器（自建 ioc）
    auto run_vless_connect(const Vless::Address &Target,
                           Vless::ClientConfig ccfg = {},
                           Vless::ServerConfig scfg = {})
        -> ConnectResult
    {
        ConnectResult out;
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto ChainStateObj = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), Preview::Testing::AcceptEchoLoop(echo_acceptor),
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
                opts.AcceptProtocol = MakeAcceptVless(scfg);
                opts.Dial = [ChainStateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vless_upstream(ChainStateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                if (start_rc != Fault::Code::Success)
                {
                    out.Err = Preview::Error::IoError;
                    co_return;
                }
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer d(ioc.get_executor());
                auto raw = co_await d.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    out.Err = Preview::Error::IoError;
                    listener.Stop();
                    co_return;
                }
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg, Target);
                out.Err = err;
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                const std::string payload = "chain payload";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->async_read_some(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                out.Echo.assign(reinterpret_cast<const char *>(buf.data()), got);
                out.Host = ChainStateObj->RequestedHost;
                out.Port = ChainStateObj->RequestedPort;
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        return out;
    }

    TEST(TcpListener, VlessTcpConnectFullChain)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto ChainStateObj = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();

        auto on_upstream_error = [upstream_ep](const std::exception_ptr &ep)
        {
            if (ep)
            {
                *upstream_ep = ep;
            }
        };
        net::co_spawn(ioc.get_executor(), Preview::Testing::AcceptEchoLoop(echo_acceptor),
                      std::move(on_upstream_error));

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                Vless::ServerConfig scfg;
                scfg.uuid = test_uuid();
                opts.AcceptProtocol = MakeAcceptVless(scfg);
                opts.Dial = [ChainStateObj](const Network::Target &Target)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vless_upstream(ChainStateObj, Target);
                };
                opts.RelayIdleTimeout = std::chrono::seconds(2);
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool handshake_ok = false;
        std::string echo_back;
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
                if (ec || !raw)
                {
                    co_return;
                }

                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                const auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Domain,
                                   "example.com", 443});
                handshake_ok = err == Error::None && proxy != nullptr;
                if (!proxy)
                {
                    co_return;
                }

                const std::string payload = "vless runtime payload";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                std::array<std::byte, 128> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->async_read_some(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                echo_back.assign(reinterpret_cast<const char *>(buf.data()),
                                 got);
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });

        EXPECT_TRUE(handshake_ok);
        EXPECT_EQ(ChainStateObj->RequestedHost, "example.com");
        EXPECT_EQ(ChainStateObj->RequestedPort, "443");
        EXPECT_EQ(echo_back, "vless runtime payload");
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessTcpConnectBadUuid)
    {
        // 服务端期望 test_uuid，客户端使用全零 → 握手被拒。
        // Xray 语义：UUID 不匹配时服务端静默断开（不发响应），
        // 客户端读响应遇 EOF → 传输错误（非 bad_auth 码）。
        Vless::ServerConfig scfg;
        scfg.uuid = test_uuid();
        const auto r = run_vless_connect(
            Vless::Address{Vless::AddressType::Domain, "example.net", 22},
            Vless::ClientConfig{}, scfg);
        EXPECT_NE(r.Err, Error::None);
        EXPECT_TRUE(r.Echo.empty());
    }

    TEST(TcpListener, VlessTcpConnectDialRefused)
    {
        net::io_context ioc;
        Runtime::TcpListener listener(
            ioc.get_executor(),
            [](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                Vless::ServerConfig scfg;
                scfg.uuid = test_uuid();
                opts.AcceptProtocol = MakeAcceptVless(scfg);
                // 上游永远连接被拒：VLESS 无错误应答机制，
                // 拨号失败后会话终止，客户端应读到 EOF
                opts.Dial = [](const Network::Target &)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return std::pair{
                        Fault::Code::ConnectionRefused,
                        SharedTransmission{}};
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool saw_close = false;
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
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                // 拨号失败 → 会话终止 → 读侧 EOF/错误
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                saw_close = (n == 0 || ec != std::error_code{});
                proxy->Close();
                listener.Stop();
            });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, VlessTcpConnectIpv4)
    {
        const auto r = run_vless_connect(
            Vless::Address{Vless::AddressType::Ipv4, "93.184.216.34", 80});
        EXPECT_EQ(r.Err, Error::None);
        EXPECT_EQ(r.Echo, "chain payload");
        EXPECT_EQ(r.Host, "93.184.216.34");
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, VlessTcpConnectIpv6)
    {
        // Preview 对 IPv6 的 host 采用 16 字节原始二进制约定（同 Dgram）
        const std::array<std::uint8_t, 16> Bytes = {
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46};
        const std::string v6host(reinterpret_cast<const char *>(Bytes.data()),
                                 Bytes.size());
        const auto r = run_vless_connect(
            Vless::Address{Vless::AddressType::Ipv6, v6host, 443});
        EXPECT_EQ(r.Err, Error::None);
        EXPECT_EQ(r.Echo, "chain payload");
        EXPECT_EQ(r.Host, v6host);
        EXPECT_EQ(r.Port, "443");
    }

    TEST(TcpListener, VlessTcpConnectHalfCloseClient)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto ChainStateObj = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), Preview::Testing::AcceptEchoLoop(echo_acceptor),
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
                Vless::ServerConfig scfg;
                scfg.uuid = test_uuid();
                opts.AcceptProtocol = MakeAcceptVless(scfg);
                opts.Dial = [ChainStateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vless_upstream(ChainStateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        std::string echo_back;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                const auto port = listener.LocalEndpoint().port();
                std::error_code ec;
                Network::Dialer::Dialer d(ioc.get_executor());
                auto raw = co_await d.Connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                const std::string payload = "half Close payload";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                // 半关闭客户端写方向（底层 Reliable），下行仍可读
                co_await net::post(ioc, net::use_awaitable);
                if (auto rel = std::dynamic_pointer_cast<Transport::Reliable>(
                        proxy->Underlying()))
                {
                    rel->ShutdownWrite();
                }
                std::array<std::byte, 64> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->async_read_some(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                echo_back.assign(reinterpret_cast<const char *>(buf.data()), got);
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_EQ(echo_back, "half Close payload");
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessTcpConnectIdleTimeout)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto ChainStateObj = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), Preview::Testing::AcceptEchoLoop(echo_acceptor),
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
                Vless::ServerConfig scfg;
                scfg.uuid = test_uuid();
                opts.AcceptProtocol = MakeAcceptVless(scfg);
                opts.Dial = [ChainStateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vless_upstream(ChainStateObj, t);
                };
                opts.RelayIdleTimeout = std::chrono::milliseconds(100);
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool closed = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                const auto port = listener.LocalEndpoint().port();
                std::error_code ec;
                Network::Dialer::Dialer d(ioc.get_executor());
                auto raw = co_await d.Connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                closed = (n == 0 || ec != std::error_code{});
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(closed);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessTrafficReport)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto ChainStateObj = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), Preview::Testing::AcceptEchoLoop(echo_acceptor),
                      [eph](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *eph = ep;
                          }
                      });
        TrafficRecorder recorder;
        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                Vless::ServerConfig scfg;
                scfg.uuid = test_uuid();
                opts.AcceptProtocol = MakeAcceptVless(scfg);
                opts.Dial = [ChainStateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vless_upstream(ChainStateObj, t);
                };
                opts.traffic = &recorder;
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                const auto port = listener.LocalEndpoint().port();
                std::error_code ec;
                Network::Dialer::Dialer d(ioc.get_executor());
                auto raw = co_await d.Connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                const std::string payload = "traffic payload";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                proxy->Close();
                // 等待 relay 收尾并上报流量
                net::steady_timer t(ioc);
                for (int i = 0; i < 300 && recorder.Calls == 0; ++i)
                {
                    t.expires_after(std::chrono::milliseconds(10));
                    co_await t.async_wait(net::use_awaitable);
                }
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_GT(recorder.Calls, 0);
        EXPECT_GE(recorder.Up, std::string("traffic payload").size());
        EXPECT_GE(recorder.Down, std::string("traffic payload").size());
        // 认证结果传入 Middleware：identity 为握手 UUID 的十六进制
        EXPECT_EQ(recorder.Identity, ToHex(test_uuid()));
    }

    TEST(TcpListener, VlessTcpConnectUpstreamAbort)
    {
        net::io_context ioc;
        Tcp::acceptor up_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto up_port = up_acceptor.local_endpoint().port();
        auto ChainStateObj = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), up_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), AcceptAndClose(up_acceptor),
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
                Vless::ServerConfig scfg;
                scfg.uuid = test_uuid();
                opts.AcceptProtocol = MakeAcceptVless(scfg);
                opts.Dial = [ChainStateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vless_upstream(ChainStateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool saw_close = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                const auto port = listener.LocalEndpoint().port();
                std::error_code ec;
                Network::Dialer::Dialer d(ioc.get_executor());
                auto raw = co_await d.Connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                Vless::ClientConfig ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await Vless::Connect(
                    std::move(raw), ccfg,
                    Vless::Address{Vless::AddressType::Domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                // 上游 Accept 后立即 Close → 读侧 EOF/错误
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                saw_close = (n == 0 || ec != std::error_code{});
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                up_acceptor.close(close_ec);
            });
        EXPECT_TRUE(saw_close);
        EXPECT_FALSE(*upstream_ep);
    }

} // namespace
