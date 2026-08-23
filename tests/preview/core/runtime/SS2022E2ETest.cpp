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

#include <common/core/fault/code.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/adapter/protocol_adapter.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/shadowsocks2022/shadowsocks2022.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;
    using preview::runtime::make_accept_ss2022;

    // 公共样板（run_coro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::accept_echo_loop;
    using psm::testing::chain_state;
    using psm::testing::connect_result;
    using psm::testing::run_coro;
    using psm::testing::tcp_echo_server;

    /// SS2022 纵向测试共享状态（复用公共 chain_state）
    using ss2022_chain_state = chain_state;

    /// 连接 SS2022 纵向测试的回环上游（复用公共 dial_upstream）
    auto dial_ss2022_upstream(
        const std::shared_ptr<ss2022_chain_state> &state,
        const network::target &target)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        co_return co_await psm::testing::dial_upstream(state, target);
    }

    auto run_ss2022_connect(const shadowsocks2022::address &target,
                            shadowsocks2022::client_config ccfg = {},
                            shadowsocks2022::server_config scfg = {})
        -> connect_result
    {
        connect_result out;
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<ss2022_chain_state>(
            ss2022_chain_state{ioc.get_executor(), echo_port});
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_acceptor),
                      [](const std::exception_ptr &) {});

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_ss2022(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_ss2022_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                if (start_rc != fault::code::success)
                {
                    out.err = error::io_error;
                    co_return;
                }
                const auto listen_port = listener.local_endpoint().port();
                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    out.err = error::io_error;
                    listener.stop();
                    co_return;
                }
                auto [err, proxy] = co_await shadowsocks2022::connect(std::move(raw), ccfg, target);
                out.err = err;
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "ss2022 runtime payload";
                co_await proxy->async_write(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                std::size_t got = 0;
                while (!ec && got < payload.size())
                {
                    const auto n = co_await proxy->async_read_some(
                        std::span<std::byte>(buf).subspan(got), ec);
                    if (n == 0) break;
                    got += n;
                }
                out.echo.assign(reinterpret_cast<const char *>(buf.data()), got);
                out.host = chain_state->requested_host;
                out.port = chain_state->requested_port;
                proxy->close();
                listener.stop();
                boost::system::error_code ce;
                echo_acceptor.close(ce);
            });
        return out;
    }

    TEST(TcpListener, SS2022TcpConnectFullChain)
    {
        const auto r = run_ss2022_connect(
            shadowsocks2022::address{shadowsocks2022::address_type::domain, "example.com", 443},
            shadowsocks2022::client_config{"secret"},
            shadowsocks2022::server_config{"secret"});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "ss2022 runtime payload");
        EXPECT_EQ(r.host, "example.com");
        EXPECT_EQ(r.port, "443");
    }

    TEST(TcpListener, SS2022TcpConnectIpv4)
    {
        const auto r = run_ss2022_connect(
            shadowsocks2022::address{shadowsocks2022::address_type::ipv4, "1.2.3.4", 80},
            shadowsocks2022::client_config{"secret"},
            shadowsocks2022::server_config{"secret"});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "ss2022 runtime payload");
        EXPECT_EQ(r.host, "1.2.3.4");
        EXPECT_EQ(r.port, "80");
    }

    TEST(TcpListener, SS2022TcpConnectBadPassword)
    {
        const auto r = run_ss2022_connect(
            shadowsocks2022::address{shadowsocks2022::address_type::domain, "example.net", 22},
            shadowsocks2022::client_config{"wrong"},
            shadowsocks2022::server_config{"right"});
        EXPECT_NE(r.err, error::none);
        EXPECT_TRUE(r.echo.empty());
    }

    TEST(TcpListener, SS2022TcpConnectDialRefused)
    {
        net::io_context ioc;
        runtime::tcp_listener listener(
            ioc.get_executor(),
            [](shared_transmission, std::size_t) -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_ss2022(shadowsocks2022::server_config{"secret"});
                opts.dial = [](const network::target &)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return std::pair{fault::code::connection_refused, shared_transmission{}};
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });
        bool saw_close = false;
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            const auto start_rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
            EXPECT_EQ(start_rc, fault::code::success);
            const auto listen_port = listener.local_endpoint().port();
            std::error_code ec;
            network::dialer::dialer dialer(ioc.get_executor());
            auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
            if (ec || !raw) co_return;
            auto [err, proxy] = co_await shadowsocks2022::connect(
                std::move(raw), shadowsocks2022::client_config{"secret"},
                shadowsocks2022::address{shadowsocks2022::address_type::domain, "example.com", 80});
            if (!proxy) { listener.stop(); co_return; }
            std::array<std::byte, 8> buf{};
            const auto n = co_await proxy->async_read_some(buf, ec);
            saw_close = (n == 0 || ec);
            proxy->close();
            listener.stop();
        });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, SS2022TrafficIdentity)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<ss2022_chain_state>(ss2022_chain_state{ioc.get_executor(), echo_port});
        auto recorder = std::make_shared<psm::testing::traffic_recorder>();
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_acceptor),
                      [](const std::exception_ptr &) {});
        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t) -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_ss2022(shadowsocks2022::server_config{"secret"});
                opts.traffic = recorder.get();
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_ss2022_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            const auto start_rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
            EXPECT_EQ(start_rc, fault::code::success);
            const auto listen_port = listener.local_endpoint().port();
            std::error_code ec;
            network::dialer::dialer dialer(ioc.get_executor());
            auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
            if (ec || !raw) co_return;
            auto [err, proxy] = co_await shadowsocks2022::connect(
                std::move(raw), shadowsocks2022::client_config{"secret"},
                shadowsocks2022::address{shadowsocks2022::address_type::domain, "example.com", 80});
            if (!proxy) { listener.stop(); co_return; }
            const std::string payload = "traffic probe";
            co_await proxy->async_write(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), payload.size()), ec);
            std::array<std::byte, 64> buf{};
            std::size_t got = 0;
            while (!ec && got < payload.size())
            {
                const auto n = co_await proxy->async_read_some(std::span<std::byte>(buf).subspan(got), ec);
                if (n == 0) break;
                got += n;
            }
            proxy->close();
            // 有界轮询等待流量上报落账（替代固定 sleep，避免慢机 flaky）
            net::steady_timer timer(ioc.get_executor());
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while ((recorder->up == 0u || recorder->down == 0u) &&
                   std::chrono::steady_clock::now() < deadline)
            {
                timer.expires_after(std::chrono::milliseconds(5));
                co_await timer.async_wait(net::use_awaitable);
            }
            listener.stop();
            boost::system::error_code ce;
            echo_acceptor.close(ce);
        });
        EXPECT_TRUE(recorder->identity.empty());
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

} // namespace
