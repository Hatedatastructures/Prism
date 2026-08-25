/**
 * @file TrojanE2ETest.cpp
 * @brief Trojan 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 * @details 与 SOCKS5/VLESS 共用同一套 runtime Session 编排：
 *          listener → recognition → adapter::MakeAcceptTrojan →
 *          Dial Middleware → relay Middleware → echo 上游。
 *          验证点：runtime 零协议特判；Trojan 仅经 adapter 提供握手与数据面。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Runtime/Adapter/ProtocolAdapter.hpp>
#include <common/Core/Runtime/Listener.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Trojan/Trojan.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;
    using Preview::Runtime::MakeAcceptTrojan;

    // 公共样板（RunCoro/echo 上游/TailReadGuarded 等见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::ChainState;
    using ConnectResult = psm::testing::ConnectResult;
    using psm::testing::RunCoro;
    using psm::testing::AcceptEchoLoop;
    using psm::testing::TailReadGuarded;
    using psm::testing::tcp_echo_server;

    using namespace boost::asio::experimental::awaitable_operators;

    /// Trojan 纵向测试共享状态（复用公共 psm::testing::ChainState）
    using trojan_chain_state = psm::testing::ChainState;

    /// 连接 Trojan 纵向测试的回环上游（复用公共 DialUpstream）
    inline auto dial_trojan_upstream(
        const std::shared_ptr<trojan_chain_state> &State,
        const Network::Target &Target)
        -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        co_return co_await psm::testing::DialUpstream(State, Target);
    }

    /// 通用 Trojan TCP 真实链路运行器（自建 ioc）
    auto run_trojan_connect(const Trojan::Address &Target,
                            Trojan::ClientConfig ccfg = {},
                            Trojan::ServerConfig scfg = {})
        -> ConnectResult
    {
        ConnectResult out;
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
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
                opts.AcceptProtocol = MakeAcceptTrojan(scfg);
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_trojan_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                if (start_rc != Fault::Code::success)
                {
                     out.Err = Preview::Error::io_error;
                    co_return;
                }
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect(
                    "127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                     out.Err = Preview::Error::io_error;
                    listener.Stop();
                    co_return;
                }
                auto [err, proxy] = co_await Trojan::Connect(
                    std::move(raw), ccfg, Target, Trojan::Command::Connect);
                 out.Err = err;
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                const std::string payload = "trojan runtime payload";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->AsyncReadSome(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                out.Echo.assign(reinterpret_cast<const char *>(buf.data()), got);
                 out.Host = StateObj->RequestedHost;
                 out.Port = StateObj->RequestedPort;
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        return out;
    }

    TEST(TcpListener, TrojanTcpConnectFullChain)
    {
        const auto r = run_trojan_connect(
            Trojan::Address{Trojan::AddressType::Domain, "example.com", 443},
            Trojan::ClientConfig{"Secret"},
            Trojan::ServerConfig{"Secret"});
        EXPECT_EQ(r.Err, Preview::Error::none);
        EXPECT_EQ(r.Echo, "trojan runtime payload");
        EXPECT_EQ(r.Host, "example.com");
        EXPECT_EQ(r.Port, "443");
    }

    TEST(TcpListener, TrojanTcpConnectIpv4)
    {
        const auto r = run_trojan_connect(
            Trojan::Address{Trojan::AddressType::Ipv4, "1.2.3.4", 80},
            Trojan::ClientConfig{"Secret"},
            Trojan::ServerConfig{"Secret"});
        EXPECT_EQ(r.Err, Preview::Error::none);
        EXPECT_EQ(r.Echo, "trojan runtime payload");
        EXPECT_EQ(r.Host, "1.2.3.4");
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, TrojanTcpConnectIpv6)
    {
        const auto r = run_trojan_connect(
            Trojan::Address{Trojan::AddressType::Ipv6, "::1", 80},
            Trojan::ClientConfig{"Secret"},
            Trojan::ServerConfig{"Secret"});
        EXPECT_EQ(r.Err, Preview::Error::none);
        EXPECT_EQ(r.Echo, "trojan runtime payload");
        // Trojan 线缆 ipv6 为 16 字节二进制（::1 → 15×0x00 + 0x01）
        EXPECT_EQ(r.Host.size(), 16u);
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, TrojanTcpConnectBadPassword)
    {
        // 服务端密码 "right"，客户端 "wrong" → 认证失败静默断（Xray 语义）
        const auto r = run_trojan_connect(
            Trojan::Address{Trojan::AddressType::Domain, "example.net", 22},
            Trojan::ClientConfig{"wrong"},
            Trojan::ServerConfig{"right"});
        // Trojan 客户端不读服务端应答，Connect 恒 success；bad Auth 表现为
        // 服务端静默断（Xray 语义）→ 数据面空（无 relay）。
        EXPECT_EQ(r.Err, Preview::Error::none);
        EXPECT_TRUE(r.Echo.empty());
    }

    TEST(TcpListener, TrojanTcpConnectDialRefused)
    {
        net::io_context ioc;
        Runtime::TcpListener listener(
            ioc.get_executor(),
            [](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptTrojan(
                    Trojan::ServerConfig{"Secret"});
                opts.Dial = [](const Network::Target &)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return std::pair{
                        Fault::Code::connection_refused,
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
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Trojan::Connect(
                    std::move(raw), Trojan::ClientConfig{"Secret"},
                    Trojan::Address{Trojan::AddressType::Domain, "example.com", 80},
                    Trojan::Command::Connect);
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->AsyncReadSome(buf, ec);
                // 拨号失败 → 会话终止 → 读侧 EOF/错误
                saw_close = (n == 0 || ec);
                proxy->Close();
                listener.Stop();
            });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, TrojanTcpConnectHalfCloseClient)
    {
        // 发送数据收到 echo 后，客户端半关闭（Shutdown 写），读侧应干净 EOF
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptTrojan(
                    Trojan::ServerConfig{"Secret"});
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_trojan_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool clean_eof = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Trojan::Connect(
                    std::move(raw), Trojan::ClientConfig{"Secret"},
                    Trojan::Address{Trojan::AddressType::Domain, "example.com", 80},
                    Trojan::Command::Connect);
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                const std::string payload = "half-Close Probe";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->AsyncReadSome(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                EXPECT_EQ(got, payload.size());
                proxy->Shutdown();
                // 半关闭后对端应发送 EOF；与看门狗竞速，超时即收口
                std::array<std::byte, 8> tail{};
                std::error_code tail_ec;
                const auto n = co_await psm::testing::TailReadGuarded(proxy, tail, tail_ec);
                // 干净 EOF：0 字节 + eof 错误码（Preview::Fault 把 asio::eof 映射为 Code::eof）
                clean_eof = (n == 0 && tail_ec == Preview::Fault::Code::eof);
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(clean_eof);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, TrojanTcpConnectIdleTimeout)
    {
        // 不发送任何数据，relay 空闲超时后会话应关闭
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptTrojan(
                    Trojan::ServerConfig{"Secret"});
                opts.RelayIdleTimeout = std::chrono::milliseconds(150);
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_trojan_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool closed = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Trojan::Connect(
                    std::move(raw), Trojan::ClientConfig{"Secret"},
                    Trojan::Address{Trojan::AddressType::Domain, "example.com", 80},
                    Trojan::Command::Connect);
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                // 不发数据，等待空闲超时
                net::steady_timer timer(ioc.get_executor(),
                                        std::chrono::milliseconds(400));
                co_await timer.async_wait(net::use_awaitable);
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->AsyncReadSome(buf, ec);
                closed = (n == 0 || ec);
                proxy->Close();
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(closed);
    }

    TEST(TcpListener, TrojanTrafficIdentity)
    {
        // 认证身份不应携带明文密码（防统计/日志泄露）
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});

        auto recorder = std::make_shared<psm::testing::TrafficRecorder>();

        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptTrojan(
                    Trojan::ServerConfig{"Secret"});
                opts.traffic = recorder.get();
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_trojan_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listener.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Trojan::Connect(
                    std::move(raw), Trojan::ClientConfig{"Secret"},
                    Trojan::Address{Trojan::AddressType::Domain, "example.com", 80},
                    Trojan::Command::Connect);
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                const std::string payload = "traffic identity Probe";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->AsyncReadSome(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                proxy->Close();
                // 有界轮询等待流量上报落账（替代固定 sleep，避免慢机 flaky）
                net::steady_timer timer(ioc.get_executor());
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                while ((recorder->up == 0u || recorder->down == 0u) &&
                       std::chrono::steady_clock::now() < deadline)
                {
                    timer.expires_after(std::chrono::milliseconds(5));
                    co_await timer.async_wait(net::use_awaitable);
                }
                listener.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(recorder->identity.empty());
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

} // namespace
