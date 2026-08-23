/**
 * @file VMessE2ETest.cpp
 * @brief VMess 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 * @details 与 SOCKS5/VLESS/Trojan 共用同一套 runtime session 编排：
 *          listener → recognition → adapter::make_accept_vmess →
 *          dial middleware → relay middleware → echo 上游。
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

#include <common/core/fault/code.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/adapter/protocol_adapter.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/vmess/vmess.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;
    using preview::runtime::make_accept_vmess;

    // 公共样板（run_coro/echo 上游/tail_read_guarded 等见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::accept_echo_loop;
    using psm::testing::chain_state;
    using psm::testing::connect_result;
    using psm::testing::make_uuid;
    using psm::testing::run_coro;
    using psm::testing::tail_read_guarded;
    using psm::testing::tcp_echo_server;
    using psm::testing::to_hex;

    using namespace boost::asio::experimental::awaitable_operators;

    /// VMess 纵向测试共享状态（复用公共 chain_state）
    using vmess_chain_state = chain_state;

    /// 测试 UUID 兼容别名
    inline auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        return make_uuid();
    }

    /// 连接 VMess 纵向测试的回环上游（复用公共 dial_upstream）
    auto dial_vmess_upstream(
        const std::shared_ptr<vmess_chain_state> &state,
        const network::target &target)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        co_return co_await psm::testing::dial_upstream(state, target);
    }

    /// 通用 VMess TCP 真实链路运行器
    auto run_vmess_connect(const vmess::address &target,
                           vmess::client_config ccfg = {},
                           vmess::server_config scfg = {})
        -> connect_result
    {
        connect_result out;
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_acceptor),
                      [eph](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *eph = ep;
                          }
                      });

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_vmess(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vmess_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
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
                auto [err, proxy] = co_await vmess::connect(
                    std::move(raw), ccfg, target, vmess::command::tcp);
                out.err = err;
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "vmess runtime payload";
                co_await proxy->async_write(
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
                out.echo.assign(reinterpret_cast<const char *>(buf.data()), got);
                out.host = chain_state->requested_host;
                out.port = chain_state->requested_port;
                proxy->close();
                listener.stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        return out;
    }

    TEST(TcpListener, VmessTcpConnectFullChain)
    {
        const auto r = run_vmess_connect(
            vmess::address{vmess::address_type::domain, "example.com", 443},
            vmess::client_config{test_uuid()},
            vmess::server_config{test_uuid()});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "vmess runtime payload");
        EXPECT_EQ(r.host, "example.com");
        EXPECT_EQ(r.port, "443");
    }

    TEST(TcpListener, VmessTcpConnectIpv4)
    {
        const auto r = run_vmess_connect(
            vmess::address{vmess::address_type::ipv4, "1.2.3.4", 80},
            vmess::client_config{test_uuid()},
            vmess::server_config{test_uuid()});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "vmess runtime payload");
        EXPECT_EQ(r.host, "1.2.3.4");
        EXPECT_EQ(r.port, "80");
    }

    TEST(TcpListener, VmessTcpConnectIpv6)
    {
        const auto r = run_vmess_connect(
            vmess::address{vmess::address_type::ipv6, "::1", 80},
            vmess::client_config{test_uuid()},
            vmess::server_config{test_uuid()});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "vmess runtime payload");
        // VMess ipv6 线缆为 16 字节二进制
        EXPECT_EQ(r.host.size(), 16u);
        EXPECT_EQ(r.port, "80");
    }

    TEST(TcpListener, VmessTcpConnectBadUuid)
    {
        // 服务端期望 test_uuid，客户端全零 → AEAD 解密失败（bad_auth/io_error）
        const auto r = run_vmess_connect(
            vmess::address{vmess::address_type::domain, "example.net", 22},
            vmess::client_config{},
            vmess::server_config{test_uuid()});
        EXPECT_NE(r.err, error::none);
        EXPECT_TRUE(r.echo.empty());
    }

    TEST(TcpListener, VmessTcpConnectDialRefused)
    {
        net::io_context ioc;
        runtime::tcp_listener listener(
            ioc.get_executor(),
            [](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_vmess(
                    vmess::server_config{test_uuid()});
                opts.dial = [](const network::target &)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return std::pair{
                        fault::code::connection_refused,
                        shared_transmission{}};
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool saw_close = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
                EXPECT_EQ(start_rc, fault::code::success);
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await vmess::connect(
                    std::move(raw), vmess::client_config{test_uuid()},
                    vmess::address{vmess::address_type::domain, "example.com", 80},
                    vmess::command::tcp);
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                saw_close = (n == 0 || ec);
                proxy->close();
                listener.stop();
            });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, VmessTcpConnectHalfCloseClient)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_vmess(
                    vmess::server_config{test_uuid()});
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vmess_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool clean_eof = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
                EXPECT_EQ(start_rc, fault::code::success);
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await vmess::connect(
                    std::move(raw), vmess::client_config{test_uuid()},
                    vmess::address{vmess::address_type::domain, "example.com", 80},
                    vmess::command::tcp);
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "half-close probe";
                co_await proxy->async_write(
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
                EXPECT_EQ(got, payload.size());
                proxy->shutdown();
                // 半关闭后对端应发送 EOF；与看门狗竞速，超时即收口
                std::array<std::byte, 8> tail{};
                std::error_code tail_ec;
                const auto n = co_await tail_read_guarded(proxy, tail, tail_ec);
                // VMess EOF 语义：服务端读到底层 EOF 后以 unexpected_eof 收口
                // （无 VMess 结束块——服务端被 relay shutdown 被动触发，无法补发）
                clean_eof = (n == 0 &&
                             tail_ec == ::preview::make_error_code(
                                            ::preview::error::unexpected_eof));
                proxy->close();
                listener.stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(clean_eof);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VmessTcpConnectIdleTimeout)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_vmess(
                    vmess::server_config{test_uuid()});
                opts.relay_idle_timeout = std::chrono::milliseconds(150);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vmess_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool closed = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
                EXPECT_EQ(start_rc, fault::code::success);
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await vmess::connect(
                    std::move(raw), vmess::client_config{test_uuid()},
                    vmess::address{vmess::address_type::domain, "example.com", 80},
                    vmess::command::tcp);
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                net::steady_timer timer(ioc.get_executor(), std::chrono::milliseconds(400));
                co_await timer.async_wait(net::use_awaitable);
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                closed = (n == 0 || ec);
                proxy->close();
                listener.stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(closed);
    }

    TEST(TcpListener, VmessTrafficIdentity)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});

        auto recorder = std::make_shared<psm::testing::traffic_recorder>();

        auto upstream_ep = std::make_shared<std::exception_ptr>();
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_acceptor),
                      [upstream_ep](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *upstream_ep = ep;
                          }
                      });

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_vmess(
                    vmess::server_config{test_uuid()});
                opts.traffic = recorder.get();
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vmess_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto start_rc = co_await listener.start(
                    tcp::endpoint(tcp::v4(), 0));
                EXPECT_EQ(start_rc, fault::code::success);
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }
                auto [err, proxy] = co_await vmess::connect(
                    std::move(raw), vmess::client_config{test_uuid()},
                    vmess::address{vmess::address_type::domain, "example.com", 80},
                    vmess::command::tcp);
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "traffic identity probe";
                co_await proxy->async_write(
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
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_EQ(recorder->identity, to_hex(test_uuid()));
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

} // namespace
