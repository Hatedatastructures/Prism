/**
 * @file TrojanE2ETest.cpp
 * @brief Trojan 纵向链路测试（链 P：代理协议 L3 经 adapter 接入缝）
 * @details 与 SOCKS5/VLESS 共用同一套 runtime session 编排：
 *          listener → recognition → adapter::make_accept_trojan →
 *          dial middleware → relay middleware → echo 上游。
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

#include <common/core/fault/code.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/adapter/protocol_adapter.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/trojan/trojan.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;
    using preview::runtime::make_accept_trojan;

    // 公共样板（run_coro/echo 上游/tail_read_guarded 等见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::chain_state;
    using psm::testing::connect_result;
    using psm::testing::run_coro;
    using psm::testing::accept_echo_loop;
    using psm::testing::tail_read_guarded;
    using psm::testing::tcp_echo_server;

    using namespace boost::asio::experimental::awaitable_operators;

    /// Trojan 纵向测试共享状态（复用公共 chain_state）
    using trojan_chain_state = chain_state;

    /// 连接 Trojan 纵向测试的回环上游（复用公共 dial_upstream）
    inline auto dial_trojan_upstream(
        const std::shared_ptr<trojan_chain_state> &state,
        const network::target &target)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        co_return co_await psm::testing::dial_upstream(state, target);
    }

    /// 通用 Trojan TCP 真实链路运行器（自建 ioc）
    auto run_trojan_connect(const trojan::address &target,
                            trojan::client_config ccfg = {},
                            trojan::server_config scfg = {})
        -> connect_result
    {
        connect_result out;
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});
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
                opts.accept_protocol = make_accept_trojan(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_trojan_upstream(chain_state, t);
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
                auto raw = co_await dialer.connect(
                    "127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    out.err = error::io_error;
                    listener.stop();
                    co_return;
                }
                auto [err, proxy] = co_await trojan::connect(
                    std::move(raw), ccfg, target, trojan::command::connect);
                out.err = err;
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "trojan runtime payload";
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

    TEST(TcpListener, TrojanTcpConnectFullChain)
    {
        const auto r = run_trojan_connect(
            trojan::address{trojan::address_type::domain, "example.com", 443},
            trojan::client_config{"secret"},
            trojan::server_config{"secret"});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "trojan runtime payload");
        EXPECT_EQ(r.host, "example.com");
        EXPECT_EQ(r.port, "443");
    }

    TEST(TcpListener, TrojanTcpConnectIpv4)
    {
        const auto r = run_trojan_connect(
            trojan::address{trojan::address_type::ipv4, "1.2.3.4", 80},
            trojan::client_config{"secret"},
            trojan::server_config{"secret"});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "trojan runtime payload");
        EXPECT_EQ(r.host, "1.2.3.4");
        EXPECT_EQ(r.port, "80");
    }

    TEST(TcpListener, TrojanTcpConnectIpv6)
    {
        const auto r = run_trojan_connect(
            trojan::address{trojan::address_type::ipv6, "::1", 80},
            trojan::client_config{"secret"},
            trojan::server_config{"secret"});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "trojan runtime payload");
        // Trojan 线缆 ipv6 为 16 字节二进制（::1 → 15×0x00 + 0x01）
        EXPECT_EQ(r.host.size(), 16u);
        EXPECT_EQ(r.port, "80");
    }

    TEST(TcpListener, TrojanTcpConnectBadPassword)
    {
        // 服务端密码 "right"，客户端 "wrong" → 认证失败静默断（Xray 语义）
        const auto r = run_trojan_connect(
            trojan::address{trojan::address_type::domain, "example.net", 22},
            trojan::client_config{"wrong"},
            trojan::server_config{"right"});
        // Trojan 客户端不读服务端应答，connect 恒 success；bad auth 表现为
        // 服务端静默断（Xray 语义）→ 数据面空（无 relay）。
        EXPECT_EQ(r.err, error::none);
        EXPECT_TRUE(r.echo.empty());
    }

    TEST(TcpListener, TrojanTcpConnectDialRefused)
    {
        net::io_context ioc;
        runtime::tcp_listener listener(
            ioc.get_executor(),
            [](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_trojan(
                    trojan::server_config{"secret"});
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
                auto [err, proxy] = co_await trojan::connect(
                    std::move(raw), trojan::client_config{"secret"},
                    trojan::address{trojan::address_type::domain, "example.com", 80},
                    trojan::command::connect);
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                // 拨号失败 → 会话终止 → 读侧 EOF/错误
                saw_close = (n == 0 || ec);
                proxy->close();
                listener.stop();
            });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, TrojanTcpConnectHalfCloseClient)
    {
        // 发送数据收到 echo 后，客户端半关闭（shutdown 写），读侧应干净 EOF
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});
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
                opts.accept_protocol = make_accept_trojan(
                    trojan::server_config{"secret"});
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_trojan_upstream(chain_state, t);
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
                auto [err, proxy] = co_await trojan::connect(
                    std::move(raw), trojan::client_config{"secret"},
                    trojan::address{trojan::address_type::domain, "example.com", 80},
                    trojan::command::connect);
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
                // 干净 EOF：0 字节 + eof 错误码（preview::fault 把 asio::eof 映射为 code::eof）
                clean_eof = (n == 0 && tail_ec == preview::fault::code::eof);
                proxy->close();
                listener.stop();
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
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});
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
                opts.accept_protocol = make_accept_trojan(
                    trojan::server_config{"secret"});
                opts.relay_idle_timeout = std::chrono::milliseconds(150);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_trojan_upstream(chain_state, t);
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
                auto [err, proxy] = co_await trojan::connect(
                    std::move(raw), trojan::client_config{"secret"},
                    trojan::address{trojan::address_type::domain, "example.com", 80},
                    trojan::command::connect);
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                // 不发数据，等待空闲超时
                net::steady_timer timer(ioc.get_executor(),
                                        std::chrono::milliseconds(400));
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

    TEST(TcpListener, TrojanTrafficIdentity)
    {
        // 认证身份不应携带明文密码（防统计/日志泄露）
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<trojan_chain_state>(
            trojan_chain_state{ioc.get_executor(), echo_port});

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
                opts.accept_protocol = make_accept_trojan(
                    trojan::server_config{"secret"});
                opts.traffic = recorder.get();
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_trojan_upstream(chain_state, t);
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
                auto [err, proxy] = co_await trojan::connect(
                    std::move(raw), trojan::client_config{"secret"},
                    trojan::address{trojan::address_type::domain, "example.com", 80},
                    trojan::command::connect);
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
        EXPECT_TRUE(recorder->identity.empty());
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

} // namespace
