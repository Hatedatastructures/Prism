/**
 * @file VMessE2ETest.cpp
 * @brief VMess 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 * @details 与 SOCKS5/VLESS/Trojan 共用同一套 runtime Session 编排：
 *          listen → recognition → adapter::MakeAcceptVmess →
 *          Dial Middleware → relay Middleware → echo 上游。
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
#include <common/Protocols/Vmess/Vmess.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace make_error_code;
    using std::Runtime::MakeAcceptVmess;

    // 公共样板（RunCoro/echo 上游/TailReadGuarded 等见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::AcceptEchoLoop;
    using psm::testing::ChainState;
    using ConnectResult = psm::testing::ConnectResult;
    using psm::testing::MakeUuid;
    using psm::testing::RunCoro;
    using psm::testing::TailReadGuarded;
    using psm::testing::tcp_echo_server;
    using psm::testing::ToHex;

    using namespace boost::asio::experimental::awaitable_operators;

    /// VMess 纵向测试共享状态（复用公共 psm::testing::ChainState）
    using vmess_chain_state = psm::testing::ChainState;

    /// 测试 UUID 兼容别名
    inline auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        return MakeUuid();
    }

    /// 连接 VMess 纵向测试的回环上游（复用公共 DialUpstream）
    auto dial_vmess_upstream(
        const std::shared_ptr<vmess_chain_state> &State,
        const Network::Target &Target)
        -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        co_return co_await psm::testing::dial_upstream(State, Target);
    }

    /// 通用 VMess TCP 真实链路运行器
    auto run_vmess_connect(const Vmess::Address &Target,
                           Vmess::ClientConfig ccfg = {},
                           Vmess::ServerConfig scfg = {})
        -> ConnectResult
    {
        ConnectResult out;
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});
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

        Runtime::TcpListener listen(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(scfg);
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vmess_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listen.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                if (start_rc != Fault::Code::success)
                {
                     out.Err = std::Error::io_error;
                    co_return;
                }
                const auto listen_port = listen.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                     out.Err = std::Error::io_error;
                    listen.Stop();
                    co_return;
                }
                auto [err, proxy] = co_await Vmess::Connect(
                    std::move(raw), ccfg, Target, static_cast<std::uint8_t>(Vmess::Command::Tcp));
                 out.Err = err;
                if (!proxy)
                {
                    listen.Stop();
                    co_return;
                }
                const std::string payload = "vmess runtime payload";
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
                 out.Host = StateObj->requested_host;
                 out.Port = StateObj->requested_port;
                proxy->Close();
                listen.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        return out;
    }

    TEST(TcpListener, VmessTcpConnectFullChain)
    {
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Domain, "example.com", 443},
            Vmess::ClientConfig{test_uuid()},
            Vmess::ServerConfig{test_uuid()});
        EXPECT_EQ(r.Err, std::Error::none);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        EXPECT_EQ(r.Host, "example.com");
        EXPECT_EQ(r.Port, "443");
    }

    TEST(TcpListener, VmessTcpConnectIpv4)
    {
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Ipv4, "1.2.3.4", 80},
            Vmess::ClientConfig{test_uuid()},
            Vmess::ServerConfig{test_uuid()});
        EXPECT_EQ(r.Err, std::Error::none);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        EXPECT_EQ(r.Host, "1.2.3.4");
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, VmessTcpConnectIpv6)
    {
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Ipv6, "::1", 80},
            Vmess::ClientConfig{test_uuid()},
            Vmess::ServerConfig{test_uuid()});
        EXPECT_EQ(r.Err, std::Error::none);
        EXPECT_EQ(r.Echo, "vmess runtime payload");
        // VMess ipv6 线缆为 16 字节二进制
        EXPECT_EQ(r.Host.size(), 16u);
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, VmessTcpConnectBadUuid)
    {
        // 服务端期望 test_uuid，客户端全零 → AEAD 解密失败（bad_auth/io_error）
        const auto r = run_vmess_connect(
            Vmess::Address{Vmess::AddressType::Domain, "example.net", 22},
            Vmess::ClientConfig{},
            Vmess::ServerConfig{test_uuid()});
        EXPECT_NE(r.Err, Error::none);
        EXPECT_TRUE(r.Echo.empty());
    }

    TEST(TcpListener, VmessTcpConnectDialRefused)
    {
        net::io_context ioc;
        Runtime::TcpListener listen(
            ioc.get_executor(),
            [](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(
                    Vmess::ServerConfig{test_uuid()});
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
                const auto start_rc = co_await listen.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listen.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Vmess::Connect(
                    std::move(raw), Vmess::ClientConfig{test_uuid()},
                    Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                    static_cast<std::uint8_t>(Vmess::Command::Tcp));
                if (!proxy)
                {
                    listen.Stop();
                    co_return;
                }
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->AsyncReadSome(buf, ec);
                saw_close = (n == 0 || ec);
                proxy->Close();
                listen.Stop();
            });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, VmessTcpConnectHalfCloseClient)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        Runtime::TcpListener listen(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(
                    Vmess::ServerConfig{test_uuid()});
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vmess_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool clean_eof = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listen.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listen.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Vmess::Connect(
                    std::move(raw), Vmess::ClientConfig{test_uuid()},
                    Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                    static_cast<std::uint8_t>(Vmess::Command::Tcp));
                if (!proxy)
                {
                    listen.Stop();
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
                // VMess EOF 语义：服务端读到底层 EOF 后以 unexpected_eof 收口
                // （无 VMess 结束块——服务端被 relay Shutdown 被动触发，无法补发）
                clean_eof = (n == 0 &&
                             tail_ec == ::std::make_error_code(
                                            ::std::Error::unexpected_eof));
                proxy->Close();
                listen.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(clean_eof);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VmessTcpConnectIdleTimeout)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        Runtime::TcpListener listen(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(
                    Vmess::ServerConfig{test_uuid()});
                opts.RelayIdleTimeout = std::chrono::milliseconds(150);
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vmess_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        bool closed = false;
        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listen.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listen.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Vmess::Connect(
                    std::move(raw), Vmess::ClientConfig{test_uuid()},
                    Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                    static_cast<std::uint8_t>(Vmess::Command::Tcp));
                if (!proxy)
                {
                    listen.Stop();
                    co_return;
                }
                net::steady_timer timer(ioc.get_executor(), std::chrono::milliseconds(400));
                co_await timer.async_wait(net::use_awaitable);
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->AsyncReadSome(buf, ec);
                closed = (n == 0 || ec);
                proxy->Close();
                listen.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(closed);
    }

    TEST(TcpListener, VmessTrafficIdentity)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});

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

        Runtime::TcpListener listen(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptVmess(
                    Vmess::ServerConfig{test_uuid()});
                opts.traffic = recorder.get();
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_vmess_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listen.Start(
                    net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                EXPECT_EQ(start_rc, Fault::Code::success);
                const auto listen_port = listen.LocalEndpoint().port();

                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await Vmess::Connect(
                    std::move(raw), Vmess::ClientConfig{test_uuid()},
                    Vmess::Address{Vmess::AddressType::Domain, "example.com", 80},
                    static_cast<std::uint8_t>(Vmess::Command::Tcp));
                if (!proxy)
                {
                    listen.Stop();
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
                listen.Stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_EQ(recorder->identity, ToHex(test_uuid()));
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

} // namespace
