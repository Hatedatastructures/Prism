/**
 * @file SS2022E2ETest.cpp
 * @brief Shadowsocks2022 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
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
#include <common/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;
    using Preview::Runtime::MakeAcceptSs2022;

    // 公共样板（RunCoro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::AcceptEchoLoop;
    using psm::testing::ChainState;
    using ConnectResult = psm::testing::ConnectResult;
    using psm::testing::RunCoro;
    using psm::testing::tcp_echo_server;

    /// SS2022 纵向测试共享状态（复用公共 psm::testing::ChainState）
    using ss2022_chain_state = psm::testing::ChainState;

    /// 连接 SS2022 纵向测试的回环上游（复用公共 DialUpstream）
    auto dial_ss2022_upstream(
        const std::shared_ptr<ss2022_chain_state> &State,
        const Network::Target &Target)
        -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        co_return co_await psm::testing::DialUpstream(State, Target);
    }

    auto run_ss2022_connect(const Shadowsocks2022::Address &Target,
                            Shadowsocks2022::ClientConfig ccfg = {},
                            Shadowsocks2022::ServerConfig scfg = {})
        -> ConnectResult
    {
        ConnectResult out;
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<ss2022_chain_state>(
            ss2022_chain_state{ioc.get_executor(), echo_port});
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
                      [](const std::exception_ptr &) {});

        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptSs2022(scfg);
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_ss2022_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                if (start_rc != Fault::Code::success)
                {
                     out.Err = Error::io_error;
                    co_return;
                }
                const auto listen_port = listener.LocalEndpoint().port();
                std::error_code ec;
                Network::Dialer::Dialer Dialer(ioc.get_executor());
                auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                     out.Err = Error::io_error;
                    listener.Stop();
                    co_return;
                }
                auto [err, proxy] = co_await Shadowsocks2022::Connect(std::move(raw), ccfg, Target);
                 out.Err = err;
                if (!proxy)
                {
                    listener.Stop();
                    co_return;
                }
                const std::string payload = "ss2022 runtime payload";
                co_await proxy->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->AsyncReadSome(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0) break;
                    got += n;
                }
                out.Echo.assign(reinterpret_cast<const char *>(buf.data()), got);
                 out.Host = StateObj->RequestedHost;
                 out.Port = StateObj->RequestedPort;
                proxy->Close();
                listener.Stop();
                boost::system::error_code ce;
                echo_acceptor.close(ce);
            });
        return out;
    }

    TEST(TcpListener, SS2022TcpConnectFullChain)
    {
        const auto r = run_ss2022_connect(
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.com", 443},
            Shadowsocks2022::ClientConfig{"Secret"},
            Shadowsocks2022::ServerConfig{"Secret"});
        EXPECT_EQ(r.Err, Error::none);
        EXPECT_EQ(r.Echo, "ss2022 runtime payload");
        EXPECT_EQ(r.Host, "example.com");
        EXPECT_EQ(r.Port, "443");
    }

    TEST(TcpListener, SS2022TcpConnectIpv4)
    {
        const auto r = run_ss2022_connect(
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Ipv4, "1.2.3.4", 80},
            Shadowsocks2022::ClientConfig{"Secret"},
            Shadowsocks2022::ServerConfig{"Secret"});
        EXPECT_EQ(r.Err, Error::none);
        EXPECT_EQ(r.Echo, "ss2022 runtime payload");
        EXPECT_EQ(r.Host, "1.2.3.4");
        EXPECT_EQ(r.Port, "80");
    }

    TEST(TcpListener, SS2022TcpConnectBadPassword)
    {
        const auto r = run_ss2022_connect(
            Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.net", 22},
            Shadowsocks2022::ClientConfig{"wrong"},
            Shadowsocks2022::ServerConfig{"right"});
        EXPECT_NE(r.Err, Error::none);
        EXPECT_TRUE(r.Echo.empty());
    }

    TEST(TcpListener, SS2022TcpConnectDialRefused)
    {
        net::io_context ioc;
        Runtime::TcpListener listener(
            ioc.get_executor(),
            [](SharedTransmission, std::size_t) -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptSs2022(Shadowsocks2022::ServerConfig{"Secret"});
                opts.Dial = [](const Network::Target &)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return std::pair{Fault::Code::connection_refused, SharedTransmission{}};
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });
        bool saw_close = false;
        RunCoro(ioc, [&]() -> net::awaitable<void>
        {
            const auto start_rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
            EXPECT_EQ(start_rc, Fault::Code::success);
            const auto listen_port = listener.LocalEndpoint().port();
            std::error_code ec;
            Network::Dialer::Dialer Dialer(ioc.get_executor());
            auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
            if (ec || !raw) co_return;
            auto [err, proxy] = co_await Shadowsocks2022::Connect(
                std::move(raw), Shadowsocks2022::ClientConfig{"Secret"},
                Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.com", 80});
            if (!proxy) { listener.Stop(); co_return; }
            std::array<std::byte, 8> buf{};
            const auto n = co_await proxy->AsyncReadSome(buf, ec);
            saw_close = (n == 0 || ec);
            proxy->Close();
            listener.Stop();
        });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, SS2022TrafficIdentity)
    {
        net::io_context ioc;
        Tcp::acceptor echo_acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto StateObj = std::make_shared<ss2022_chain_state>(ss2022_chain_state{ioc.get_executor(), echo_port});
        auto recorder = std::make_shared<psm::testing::TrafficRecorder>();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_acceptor),
                      [](const std::exception_ptr &) {});
        Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](SharedTransmission, std::size_t) -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptSs2022(Shadowsocks2022::ServerConfig{"Secret"});
                opts.traffic = recorder.get();
                opts.Dial = [StateObj](const Network::Target &t)
                    -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    co_return co_await dial_ss2022_upstream(StateObj, t);
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });
        RunCoro(ioc, [&]() -> net::awaitable<void>
        {
            const auto start_rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
            EXPECT_EQ(start_rc, Fault::Code::success);
            const auto listen_port = listener.LocalEndpoint().port();
            std::error_code ec;
            Network::Dialer::Dialer Dialer(ioc.get_executor());
            auto raw = co_await Dialer.Connect("127.0.0.1", listen_port, ec);
            if (ec || !raw) co_return;
            auto [err, proxy] = co_await Shadowsocks2022::Connect(
                std::move(raw), Shadowsocks2022::ClientConfig{"Secret"},
                Shadowsocks2022::Address{Shadowsocks2022::AddressType::Domain, "example.com", 80});
            if (!proxy) { listener.Stop(); co_return; }
            const std::string payload = "traffic Probe";
            co_await proxy->AsyncWrite(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), payload.size()), ec);
            std::array<std::byte, 64> buf{};
            std::size_t got = 0;
            while (!ec && got < payload.size())
            {
                const auto n = co_await proxy->AsyncReadSome(std::span<std::byte>(buf).subspan(got), ec);
                if (n == 0) break;
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
            boost::system::error_code ce;
            echo_acceptor.close(ce);
        });
        EXPECT_TRUE(recorder->identity.empty());
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

} // namespace
