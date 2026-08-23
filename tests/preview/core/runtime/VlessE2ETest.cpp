/**
 * @file VlessE2ETest.cpp
 * @brief VLESS 第二条纵向链路测试（阶段 4：抽象复用验证）
 * @details 与 SOCKS5 共用同一套 runtime session 编排：
 *          listener → recognition → accept_protocol(vless) →
 *          dial middleware → relay middleware → echo 上游。
 *          验证点：runtime 零协议特判（不复制 SOCKS5 的
 *          accept/post_dial 编排），VLESS 仅提供握手与数据面。
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
#include <common/core/transport/reliable.hpp>
#include <common/protocols/vless/vless.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

    // 公共样板（run_coro/echo 上游/tail_read_guarded 等见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::accept_and_close;
    using psm::testing::accept_echo_loop;
    using psm::testing::chain_state;
    using psm::testing::connect_result;
    using psm::testing::make_uuid;
    using psm::testing::run_coro;
    using psm::testing::tail_read_guarded;
    using psm::testing::tcp_echo_server;
    using psm::testing::to_hex;
    using psm::testing::traffic_recorder;

    /// VLESS 纵向测试共享状态（复用公共 chain_state）
    using vless_chain_state = chain_state;

    /// 固定测试 UUID 兼容别名（vless::uuid_len == 16）
    inline auto test_uuid() -> std::array<std::uint8_t, vless::uuid_len>
    {
        return make_uuid();
    }

    /// 构造 VLESS 服务端接入回调（UUID 校验在握手内完成，无延迟应答；经 adapter 缝）
    auto make_accept_vless(vless::server_config cfg = {})
        -> runtime::session_options::protocol_accept_fn
    {
        return runtime::make_accept_vless(std::move(cfg));
    }

    /// 连接 VLESS 纵向测试的回环上游（复用公共 dial_upstream）
    auto dial_vless_upstream(
        const std::shared_ptr<vless_chain_state> &state,
        const network::target &target)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        co_return co_await psm::testing::dial_upstream(state, target);
    }

    /// 通用 VLESS TCP 真实链路运行器（自建 ioc）
    auto run_vless_connect(const vless::address &target,
                           vless::client_config ccfg = {},
                           vless::server_config scfg = {})
        -> connect_result
    {
        connect_result out;
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
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
                opts.accept_protocol = make_accept_vless(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vless_upstream(chain_state, t);
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
                network::dialer::dialer d(ioc.get_executor());
                auto raw = co_await d.connect("127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    out.err = error::io_error;
                    listener.stop();
                    co_return;
                }
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg, target);
                out.err = err;
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "chain payload";
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

    TEST(TcpListener, VlessTcpConnectFullChain)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();

        auto on_upstream_error = [upstream_ep](const std::exception_ptr &ep)
        {
            if (ep)
            {
                *upstream_ep = ep;
            }
        };
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_acceptor),
                      std::move(on_upstream_error));

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                vless::server_config scfg;
                scfg.uuid = test_uuid();
                opts.accept_protocol = make_accept_vless(scfg);
                opts.dial = [chain_state](const network::target &target)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vless_upstream(chain_state, target);
                };
                opts.relay_idle_timeout = std::chrono::seconds(2);
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool handshake_ok = false;
        std::string echo_back;
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
                auto raw = co_await dialer.connect(
                    "127.0.0.1", listen_port, ec);
                if (ec || !raw)
                {
                    co_return;
                }

                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                const auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::domain,
                                   "example.com", 443});
                handshake_ok = err == error::none && proxy != nullptr;
                if (!proxy)
                {
                    co_return;
                }

                const std::string payload = "vless runtime payload";
                co_await proxy->async_write(
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
                proxy->close();
                listener.stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });

        EXPECT_TRUE(handshake_ok);
        EXPECT_EQ(chain_state->requested_host, "example.com");
        EXPECT_EQ(chain_state->requested_port, "443");
        EXPECT_EQ(echo_back, "vless runtime payload");
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessTcpConnectBadUuid)
    {
        // 服务端期望 test_uuid，客户端使用全零 → 握手被拒。
        // Xray 语义：UUID 不匹配时服务端静默断开（不发响应），
        // 客户端读响应遇 EOF → 传输错误（非 bad_auth 码）。
        vless::server_config scfg;
        scfg.uuid = test_uuid();
        const auto r = run_vless_connect(
            vless::address{vless::address_type::domain, "example.net", 22},
            vless::client_config{}, scfg);
        EXPECT_NE(r.err, error::none);
        EXPECT_TRUE(r.echo.empty());
    }

    TEST(TcpListener, VlessTcpConnectDialRefused)
    {
        net::io_context ioc;
        runtime::tcp_listener listener(
            ioc.get_executor(),
            [](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                vless::server_config scfg;
                scfg.uuid = test_uuid();
                opts.accept_protocol = make_accept_vless(scfg);
                // 上游永远连接被拒：VLESS 无错误应答机制，
                // 拨号失败后会话终止，客户端应读到 EOF
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
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                // 拨号失败 → 会话终止 → 读侧 EOF/错误
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                saw_close = (n == 0 || ec != std::error_code{});
                proxy->close();
                listener.stop();
            });
        EXPECT_TRUE(saw_close);
    }

    TEST(TcpListener, VlessTcpConnectIpv4)
    {
        const auto r = run_vless_connect(
            vless::address{vless::address_type::ipv4, "93.184.216.34", 80});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "chain payload");
        EXPECT_EQ(r.host, "93.184.216.34");
        EXPECT_EQ(r.port, "80");
    }

    TEST(TcpListener, VlessTcpConnectIpv6)
    {
        // preview 对 IPv6 的 host 采用 16 字节原始二进制约定（同 dgram）
        const std::array<std::uint8_t, 16> bytes = {
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46};
        const std::string v6host(reinterpret_cast<const char *>(bytes.data()),
                                 bytes.size());
        const auto r = run_vless_connect(
            vless::address{vless::address_type::ipv6, v6host, 443});
        EXPECT_EQ(r.err, error::none);
        EXPECT_EQ(r.echo, "chain payload");
        EXPECT_EQ(r.host, v6host);
        EXPECT_EQ(r.port, "443");
    }

    TEST(TcpListener, VlessTcpConnectHalfCloseClient)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
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
                vless::server_config scfg;
                scfg.uuid = test_uuid();
                opts.accept_protocol = make_accept_vless(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vless_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        std::string echo_back;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                const auto port = listener.local_endpoint().port();
                std::error_code ec;
                network::dialer::dialer d(ioc.get_executor());
                auto raw = co_await d.connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "half close payload";
                co_await proxy->async_write(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                // 半关闭客户端写方向（底层 reliable），下行仍可读
                if (auto rel = std::dynamic_pointer_cast<transport::reliable>(
                        proxy->underlying()))
                {
                    rel->shutdown_write();
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
                proxy->close();
                listener.stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_EQ(echo_back, "half close payload");
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessTcpConnectIdleTimeout)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
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
                vless::server_config scfg;
                scfg.uuid = test_uuid();
                opts.accept_protocol = make_accept_vless(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vless_upstream(chain_state, t);
                };
                opts.relay_idle_timeout = std::chrono::milliseconds(100);
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool closed = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                const auto port = listener.local_endpoint().port();
                std::error_code ec;
                network::dialer::dialer d(ioc.get_executor());
                auto raw = co_await d.connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                closed = (n == 0 || ec != std::error_code{});
                proxy->close();
                listener.stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_TRUE(closed);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessTrafficReport)
    {
        net::io_context ioc;
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), echo_port});
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
        traffic_recorder recorder;
        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                vless::server_config scfg;
                scfg.uuid = test_uuid();
                opts.accept_protocol = make_accept_vless(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vless_upstream(chain_state, t);
                };
                opts.traffic = &recorder;
                return std::make_shared<runtime::session>(std::move(opts));
            });

        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                const auto port = listener.local_endpoint().port();
                std::error_code ec;
                network::dialer::dialer d(ioc.get_executor());
                auto raw = co_await d.connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                const std::string payload = "traffic payload";
                co_await proxy->async_write(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()),
                        payload.size()),
                    ec);
                std::array<std::byte, 64> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                proxy->close();
                // 等待 relay 收尾并上报流量
                net::steady_timer t(ioc);
                for (int i = 0; i < 300 && recorder.calls == 0; ++i)
                {
                    t.expires_after(std::chrono::milliseconds(10));
                    co_await t.async_wait(net::use_awaitable);
                }
                listener.stop();
                boost::system::error_code close_ec;
                echo_acceptor.close(close_ec);
            });
        EXPECT_GT(recorder.calls, 0);
        EXPECT_GE(recorder.up, std::string("traffic payload").size());
        EXPECT_GE(recorder.down, std::string("traffic payload").size());
        // 认证结果传入 middleware：identity 为握手 UUID 的十六进制
        EXPECT_EQ(recorder.identity, to_hex(test_uuid()));
    }

    TEST(TcpListener, VlessTcpConnectUpstreamAbort)
    {
        net::io_context ioc;
        tcp::acceptor up_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto up_port = up_acceptor.local_endpoint().port();
        auto chain_state = std::make_shared<vless_chain_state>(
            vless_chain_state{ioc.get_executor(), up_port});
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), accept_and_close(up_acceptor),
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
                vless::server_config scfg;
                scfg.uuid = test_uuid();
                opts.accept_protocol = make_accept_vless(scfg);
                opts.dial = [chain_state](const network::target &t)
                    -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    co_return co_await dial_vless_upstream(chain_state, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool saw_close = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                const auto port = listener.local_endpoint().port();
                std::error_code ec;
                network::dialer::dialer d(ioc.get_executor());
                auto raw = co_await d.connect("127.0.0.1", port, ec);
                if (!raw)
                {
                    co_return;
                }
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::domain,
                                   "example.com", 80});
                if (!proxy)
                {
                    listener.stop();
                    co_return;
                }
                // 上游 accept 后立即 close → 读侧 EOF/错误
                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(buf, ec);
                saw_close = (n == 0 || ec != std::error_code{});
                proxy->close();
                listener.stop();
                boost::system::error_code close_ec;
                up_acceptor.close(close_ec);
            });
        EXPECT_TRUE(saw_close);
        EXPECT_FALSE(*upstream_ep);
    }

} // namespace
