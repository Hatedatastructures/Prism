/**
 * @file VlessUdpE2ETest.cpp
 * @brief VLESS UDP 命令纵向链路测试（阶段 4 遗留：复用 dgram 编排）
 * @details 与 SOCKS5 UDP 共用 runtime `udp_service` 抽象：
 *          client TCP 握手（cmd=udp）→ 流上 UDP 帧 → udp_tunnel
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

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/adapter/protocol_adapter.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/vless/vless.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;
    using tcp = net::ip::tcp;
    using udp = net::ip::udp;
    using namespace preview;

    // 公共样板（run_coro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::make_uuid;
    using psm::testing::run_coro;
    using psm::testing::traffic_recorder;
    using psm::testing::udp_echo_server;

    /// 固定测试 UUID 兼容别名（vless::uuid_len == 16）
    inline auto test_uuid() -> std::array<std::uint8_t, vless::uuid_len>
    {
        return make_uuid();
    }


    /// 构造 VLESS 服务端接入回调（udp 命令 → dgram 会话标记；经 adapter 缝）
    auto make_accept_vless_udp() -> runtime::session_options::protocol_accept_fn
    {
        vless::server_config cfg;
        cfg.uuid = test_uuid();
        cfg.enable_udp = true;
        return runtime::make_accept_vless(std::move(cfg));
    }

    /// 构造 UDP 数据面服务（流上帧循环；目标固定重定向到 echo）
    auto make_udp_service(std::uint16_t echo_port, std::chrono::milliseconds idle_timeout)
        -> std::function<net::awaitable<fault::code>(middleware::context &)>
    {
        return [echo_port, idle_timeout](middleware::context &ctx)
            -> net::awaitable<fault::code>
        {
            auto stream = std::dynamic_pointer_cast<vless::conn<>>(ctx.inbound);
            if (!stream)
            {
                co_return fault::code::protocol_error;
            }
            vless::udp_tunnel_options opts;
            opts.idle_timeout = idle_timeout;
            // 流量统计：session 已把 sink/identity 装配进 ctx，透传给数据面
            opts.traffic = ctx.traffic;
            opts.identity = ctx.identity;
            opts.resolve = [echo_port](const vless::address &)
                -> net::awaitable<std::pair<error, udp::endpoint>>
            {
                co_return std::pair{error::none,
                                    udp::endpoint(net::ip::make_address("127.0.0.1"),
                                                  echo_port)};
            };
            auto tunnel = std::make_shared<vless::udp_tunnel>(
                std::move(stream), std::move(opts));
            co_await tunnel->run();
            co_return fault::code::success;
        };
    }

    /// 构造一个 VLESS UDP 帧
    auto make_frame(const vless::address &target, std::string_view payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> frame;
        vless::build_udp_pkt(
            target,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
            frame);
        return frame;
    }

    /// 客户端流上往返一次：写帧 → 读回帧 → 解析
    struct roundtrip_result
    {
        std::string echo;
        vless::address src;
        bool ok{false};
    };

    /// 客户端通过协议连接（流）发送一帧并接收回帧
    auto stream_roundtrip(const std::shared_ptr<vless::conn<>> &proxy,
                          const std::vector<std::uint8_t> &frame)
        -> net::awaitable<roundtrip_result>
    {
        roundtrip_result out;
        std::error_code ec;
        std::size_t done = 0;
        auto frame_span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(frame.data()), frame.size());
        while (done < frame.size())
        {
            const auto written = co_await proxy->async_write_some(
                frame_span.subspan(done), ec);
            if (ec)
            {
                co_return out;
            }
            done += written;
        }
        std::array<std::byte, 65535> rx{};
        std::error_code rec;
        // 看门狗竞速：数据面断裂时失败而非挂死（对齐 helpers 头范式）
        net::steady_timer wd(proxy->executor());
        wd.expires_after(std::chrono::seconds(2));
        auto result = co_await (proxy->async_read_some(std::span(rx), rec) ||
                                wd.async_wait(net::use_awaitable));
        if (result.index() == 1 || rec)
        {
            co_return out;
        }
        const auto n = std::get<0>(std::move(result));
        if (n == 0)
        {
            co_return out;
        }
        vless::address src;
        std::span<const std::uint8_t> payload;
        if (vless::parse_udp_pkt(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(rx.data()), n),
                src, payload) != error::none)
        {
            co_return out;
        }
        out.echo.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
        out.src = std::move(src);
        out.ok = true;
        co_return out;
    }

    TEST(TcpListener, VlessUdpConnectEcho)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(udp::v4(), oec);
        echo_sock.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        ASSERT_FALSE(oec);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), udp_echo_server(std::move(echo_sock)),
                      [eph](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              *eph = ep;
                          }
                      });

        auto recorder = std::make_shared<traffic_recorder>();
        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_vless_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                opts.traffic = recorder.get();
                return std::make_shared<runtime::session>(std::move(opts));
            });

        std::string echo1;
        std::string echo2;
        bool handshake_ok = false;
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
                if (!raw)
                {
                    co_return;
                }
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::ipv4, "127.0.0.1", 0},
                    vless::command::udp);
                handshake_ok = err == error::none && proxy != nullptr;
                if (!proxy)
                {
                    co_return;
                }

                const auto frame1 = make_frame(
                    vless::address{vless::address_type::domain, "example.com", 53},
                    "vless udp one");
                const auto r1 = co_await stream_roundtrip(proxy, frame1);
                echo1 = r1.echo;

                const auto frame2 = make_frame(
                    vless::address{vless::address_type::ipv4, "8.8.8.8", 443},
                    "vless udp two");
                const auto r2 = co_await stream_roundtrip(proxy, frame2);
                echo2 = r2.echo;

                proxy->close();
                // 有界轮询等数据面退出并上报流量（对齐 TrojanTrafficIdentity 样板）
                net::steady_timer timer(ioc);
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                while (recorder->calls == 0 &&
                       std::chrono::steady_clock::now() < deadline)
                {
                    timer.expires_after(std::chrono::milliseconds(5));
                    co_await timer.async_wait(net::use_awaitable);
                }
                listener.stop();
            });

        EXPECT_TRUE(handshake_ok);
        EXPECT_EQ(echo1, "vless udp one");
        EXPECT_EQ(echo2, "vless udp two");
        EXPECT_FALSE(*upstream_ep);
        // UDP 数据面流量必须经 traffic sink 上报（up/down 口径与 relay 一致）
        EXPECT_GT(recorder->calls, 0);
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

    TEST(TcpListener, VlessUdpConnectIdleTimeout)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(udp::v4(), oec);
        echo_sock.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        ASSERT_FALSE(oec);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), udp_echo_server(std::move(echo_sock)),
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
                opts.accept_protocol = make_accept_vless_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::milliseconds(120));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool closed = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (!raw)
                {
                    co_return;
                }
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::ipv4, "127.0.0.1", 0},
                    vless::command::udp);
                if (!proxy)
                {
                    co_return;
                }
                // 空闲等待（超过服务端 idle_timeout）→ 流被关闭
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::milliseconds(400));
                co_await t.async_wait(net::use_awaitable);

                std::array<std::byte, 8> buf{};
                const auto n = co_await proxy->async_read_some(std::span(buf), ec);
                closed = (n == 0 || ec != std::error_code{});

                proxy->close();
                listener.stop();
            });

        EXPECT_TRUE(closed);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, VlessUdpConnectStreamEofTerminates)
    {
        net::io_context ioc;
        udp::socket echo_sock(ioc.get_executor());
        boost::system::error_code oec;
        echo_sock.open(udp::v4(), oec);
        echo_sock.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0), oec);
        ASSERT_FALSE(oec);
        const auto echo_port = echo_sock.local_endpoint().port();
        auto upstream_ep = std::make_shared<std::exception_ptr>();
        auto eph = upstream_ep;
        net::co_spawn(ioc.get_executor(), udp_echo_server(std::move(echo_sock)),
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
                opts.accept_protocol = make_accept_vless_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool first_ok = false;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                const auto listen_port = listener.local_endpoint().port();

                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect("127.0.0.1", listen_port, ec);
                if (!raw)
                {
                    co_return;
                }
                vless::client_config ccfg;
                ccfg.uuid = test_uuid();
                auto [err, proxy] = co_await vless::connect(
                    std::move(raw), ccfg,
                    vless::address{vless::address_type::ipv4, "127.0.0.1", 0},
                    vless::command::udp);
                if (!proxy)
                {
                    co_return;
                }
                // 先验证一次往返（数据面已建立）
                const auto frame = make_frame(
                    vless::address{vless::address_type::domain, "example.com", 53},
                    "first round");
                const auto r = co_await stream_roundtrip(proxy, frame);
                first_ok = r.ok;

                // 关闭流（客户端断开）→ 数据面随 EOF 终止，无需再验证回包
                proxy->close();
                listener.stop();
            });

        EXPECT_TRUE(first_ok);
        EXPECT_FALSE(*upstream_ep);
    }

} // namespace
