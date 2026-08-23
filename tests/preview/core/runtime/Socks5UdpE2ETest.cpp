/**
 * @file Socks5UdpE2ETest.cpp
 * @brief SOCKS5 UDP ASSOCIATE 纵向链路测试（阶段 3 遗留：真实 UDP 数据面）
 * @details 与 TCP 链路共用 runtime session 编排，验证 dgram 分支：
 *          client TCP 握手 UDP_ASSOCIATE → BND 端口 →
 *          client UDP 帧 → udp_assoc 解帧 → 上游 echo → 封帧回包。
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

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/adapter/protocol_adapter.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/socks5/socks5.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using udp = net::ip::udp;
    using namespace preview;

    // 公共样板（run_coro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::run_coro;
    using psm::testing::traffic_recorder;
    using psm::testing::udp_echo_server;


    /// 构造 SOCKS5 服务端接入回调（UDP_ASSOCIATE → dgram 会话标记）
    auto make_accept_socks5_udp() -> runtime::session_options::protocol_accept_fn
    {
        socks5::server_config cfg;
        cfg.enable_udp = true;
        // UDP_ASSOCIATE 应答必须由数据面 bind 后发送（携带 BND），
        // 不能使用握手默认的 0.0.0.0:0
        cfg.defer_connect_reply = true;
        return runtime::make_accept_socks5(std::move(cfg));
    }

    /// 构造 UDP 数据面服务（bind → BND → 帧循环；目标由 resolve 决定）
    auto make_udp_service(
        std::function<net::awaitable<std::pair<error, udp::endpoint>>(
            const socks5::address &)> resolve,
        std::chrono::milliseconds idle_timeout)
        -> std::function<net::awaitable<fault::code>(middleware::context &)>
    {
        return [resolve = std::move(resolve), idle_timeout](middleware::context &ctx)
            -> net::awaitable<fault::code>
        {
            auto tcp = std::dynamic_pointer_cast<socks5::conn<>>(ctx.inbound);
            if (!tcp)
            {
                co_return fault::code::protocol_error;
            }
            socks5::udp_assoc_options opts;
            opts.idle_timeout = idle_timeout;
            opts.resolve = std::move(resolve);
            // 流量统计：session 已把 sink/identity 装配进 ctx，透传给数据面
            opts.traffic = ctx.traffic;
            opts.identity = ctx.identity;
            auto svc = std::make_shared<socks5::udp_assoc>(
                ctx.inbound->executor(), std::move(tcp), std::move(opts));
            if (co_await svc->bind_and_reply() != error::none)
            {
                co_return fault::code::io_error;
            }
            co_await svc->run();
            co_return fault::code::success;
        };
    }

    /// 构造 UDP 数据面服务（目标固定重定向到 echo 端点）
    auto make_udp_service(std::uint16_t echo_port, std::chrono::milliseconds idle_timeout)
        -> std::function<net::awaitable<fault::code>(middleware::context &)>
    {
        return make_udp_service(
            [echo_port](const socks5::address &)
                -> net::awaitable<std::pair<error, udp::endpoint>>
            {
                co_return std::pair{error::none,
                                    udp::endpoint(net::ip::make_address("127.0.0.1"),
                                                  echo_port)};
            },
            idle_timeout);
    }

    /// 构造一个 SOCKS5 UDP 帧
    auto make_frame(const socks5::address &target, std::string_view payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> frame;
        socks5::build_udp_datagram(
            target,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
            frame);
        return frame;
    }

    /// 客户端 UDP 收发一次（发帧 + 收帧 + 解析）
    struct udp_roundtrip_result
    {
        std::string echo;
        socks5::address src;
        bool ok{false};
    };

    /// 客户端通过真实 UDP socket 与代理数据面往返一次
    auto udp_roundtrip(udp::socket &cudp, const udp::endpoint &bnd_ep,
                       const std::vector<std::uint8_t> &frame)
        -> net::awaitable<udp_roundtrip_result>
    {
        udp_roundtrip_result out;
        boost::system::error_code ec;
        co_await cudp.async_send_to(net::buffer(frame), bnd_ep,
                                    net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            co_return out;
        }
        std::array<std::byte, 65535> rx{};
        udp::endpoint src_ep;
        // 看门狗竞速：数据面断裂时失败而非挂死
        net::steady_timer wd(cudp.get_executor());
        wd.expires_after(std::chrono::seconds(2));
        using boost::asio::experimental::awaitable_operators::operator||;
        auto result = co_await (cudp.async_receive_from(
                                    net::buffer(rx), src_ep,
                                    net::redirect_error(net::use_awaitable, ec)) ||
                                wd.async_wait(net::use_awaitable));
        if (result.index() == 1 || ec)
        {
            co_return out;
        }
        const auto n = std::get<0>(std::move(result));
        socks5::address src;
        std::span<const std::uint8_t> payload;
        if (socks5::parse_udp_datagram(
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

    TEST(TcpListener, Socks5UdpAssociateEcho)
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
                opts.accept_protocol = make_accept_socks5_udp();
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

                // TCP 握手 UDP_ASSOCIATE → BND
                std::error_code ec;
                network::dialer::dialer dialer(ioc.get_executor());
                auto raw = co_await dialer.connect(
                    "127.0.0.1", listen_port, ec);
                if (!raw)
                {
                    co_return;
                }
                auto [err, conn] = co_await socks5::connect(
                    std::move(raw), socks5::client_config{},
                    socks5::address{socks5::address_type::ipv4, "127.0.0.1", 0},
                    socks5::command::udp_associate);
                handshake_ok = err == error::none && conn != nullptr;
                if (!conn)
                {
                    co_return;
                }
                const auto bnd = conn->bind_endpoint();
                const udp::endpoint bnd_ep(net::ip::make_address(bnd.host), bnd.port);
                EXPECT_EQ(bnd.type, socks5::address_type::ipv4);

                // 客户端真实 UDP socket → 帧往返
                udp::socket cudp(ioc.get_executor());
                cudp.open(udp::v4(), oec);
                cudp.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                const auto frame1 = make_frame(
                    socks5::address{socks5::address_type::domain, "example.com", 53},
                    "udp payload one");
                const auto r1 = co_await udp_roundtrip(cudp, bnd_ep, frame1);
                echo1 = r1.echo;

                const auto frame2 = make_frame(
                    socks5::address{socks5::address_type::ipv4, "8.8.8.8", 443},
                    "udp payload two");
                const auto r2 = co_await udp_roundtrip(cudp, bnd_ep, frame2);
                echo2 = r2.echo;

                cudp.close();
                conn->close();
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
        EXPECT_EQ(echo1, "udp payload one");
        EXPECT_EQ(echo2, "udp payload two");
        EXPECT_FALSE(*upstream_ep);
        // UDP 数据面流量必须经 traffic sink 上报（up/down 口径与 relay 一致）
        EXPECT_GT(recorder->calls, 0);
        EXPECT_GT(recorder->up, 0u);
        EXPECT_GT(recorder->down, 0u);
    }

    TEST(TcpListener, Socks5UdpAssociateBadFrame)
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
                opts.accept_protocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        std::string echo_after_bad;
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
                auto [err, conn] = co_await socks5::connect(
                    std::move(raw), socks5::client_config{},
                    socks5::address{socks5::address_type::ipv4, "127.0.0.1", 0},
                    socks5::command::udp_associate);
                if (!conn)
                {
                    co_return;
                }
                const auto bnd = conn->bind_endpoint();
                const udp::endpoint bnd_ep(net::ip::make_address(bnd.host), bnd.port);

                udp::socket cudp(ioc.get_executor());
                cudp.open(udp::v4(), oec);
                cudp.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                // 非法帧：FRAG=1（不支持分片），应被丢弃且不中断关联
                std::vector<std::uint8_t> bad = {0x00, 0x00, 0x01, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x35, 'x'};
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(bad), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));

                // 合法帧仍可往返
                const auto frame = make_frame(
                    socks5::address{socks5::address_type::domain, "example.com", 53},
                    "after bad frame");
                const auto r = co_await udp_roundtrip(cudp, bnd_ep, frame);
                echo_after_bad = r.echo;

                cudp.close();
                conn->close();
                listener.stop();
            });

        EXPECT_EQ(echo_after_bad, "after bad frame");
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, Socks5UdpAssociateIdleTimeout)
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
                opts.accept_protocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::milliseconds(120));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool timeout_closed = false;
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
                auto [err, conn] = co_await socks5::connect(
                    std::move(raw), socks5::client_config{},
                    socks5::address{socks5::address_type::ipv4, "127.0.0.1", 0},
                    socks5::command::udp_associate);
                if (!conn)
                {
                    co_return;
                }
                const auto bnd = conn->bind_endpoint();
                const udp::endpoint bnd_ep(net::ip::make_address(bnd.host), bnd.port);

                udp::socket cudp(ioc.get_executor());
                cudp.open(udp::v4(), oec);
                cudp.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                // 空闲等待（超过服务端 idle_timeout）
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::milliseconds(400));
                co_await t.async_wait(net::use_awaitable);

                // 超时后数据面已关闭：发包无回包（等待 300ms 判定）
                const auto frame = make_frame(
                    socks5::address{socks5::address_type::domain, "example.com", 53},
                    "too late");
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(frame), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));

                std::array<std::byte, 512> rx{};
                udp::endpoint src_ep;
                net::steady_timer wait(ioc);
                wait.expires_after(std::chrono::milliseconds(300));
                auto recv = cudp.async_receive_from(
                    net::buffer(rx), src_ep, net::redirect_error(net::use_awaitable, sock_ec));
                auto wait_aw = wait.async_wait(net::use_awaitable);
                using boost::asio::experimental::awaitable_operators::operator||;
                const auto res = co_await (std::move(recv) || std::move(wait_aw));
                // 数据面已关闭：无回包（超时）或端口关闭触发 ICMP 错误
                timeout_closed = res.index() == 1 ||
                                 sock_ec != boost::system::error_code{};

                cudp.close();
                conn->close();
                listener.stop();
            });

        EXPECT_TRUE(timeout_closed);
        EXPECT_FALSE(*upstream_ep);
    }

    TEST(TcpListener, Socks5UdpAssociateTcpCloseTerminates)
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
                opts.accept_protocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(echo_port, std::chrono::seconds(5));
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool terminated = false;
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
                auto [err, conn] = co_await socks5::connect(
                    std::move(raw), socks5::client_config{},
                    socks5::address{socks5::address_type::ipv4, "127.0.0.1", 0},
                    socks5::command::udp_associate);
                if (!conn)
                {
                    co_return;
                }
                const auto bnd = conn->bind_endpoint();
                const udp::endpoint bnd_ep(net::ip::make_address(bnd.host), bnd.port);

                // 先验证一次往返（数据面已建立）
                udp::socket cudp(ioc.get_executor());
                cudp.open(udp::v4(), oec);
                cudp.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
                const auto frame = make_frame(
                    socks5::address{socks5::address_type::domain, "example.com", 53},
                    "first round");
                const auto r = co_await udp_roundtrip(cudp, bnd_ep, frame);
                EXPECT_TRUE(r.ok);

                // 关闭 TCP 控制连接 → 数据面应终止
                conn->close();
                net::steady_timer t(ioc);
                t.expires_after(std::chrono::milliseconds(200));
                co_await t.async_wait(net::use_awaitable);

                // 再发包：无回包（等待 300ms 判定）
                const auto frame2 = make_frame(
                    socks5::address{socks5::address_type::domain, "example.com", 53},
                    "after tcp close");
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(frame2), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));
                std::array<std::byte, 512> rx{};
                udp::endpoint src_ep;
                net::steady_timer wait(ioc);
                wait.expires_after(std::chrono::milliseconds(300));
                auto recv = cudp.async_receive_from(
                    net::buffer(rx), src_ep, net::redirect_error(net::use_awaitable, sock_ec));
                auto wait_aw = wait.async_wait(net::use_awaitable);
                using boost::asio::experimental::awaitable_operators::operator||;
                const auto res = co_await (std::move(recv) || std::move(wait_aw));
                // 数据面已随 TCP 关闭终止：无回包（超时）或 ICMP 错误
                terminated = res.index() == 1 ||
                             sock_ec != boost::system::error_code{};

                cudp.close();
                listener.stop();
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

        runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](shared_transmission, std::size_t)
                -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_socks5_udp();
                opts.udp_service = make_udp_service(
                    [](const socks5::address &)
                        -> net::awaitable<std::pair<error, udp::endpoint>>
                    {
                        // 黑洞端点：无监听者、无回包
                        co_return std::pair{error::none,
                                            udp::endpoint(net::ip::make_address("127.0.0.1"), 1)};
                    },
                    idle_to);
                return std::make_shared<runtime::session>(std::move(opts));
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
                    listener.stop();
                    co_return;
                }
                auto [err, conn] = co_await socks5::connect(
                    std::move(raw), socks5::client_config{},
                    socks5::address{socks5::address_type::ipv4, "127.0.0.1", 0},
                    socks5::command::udp_associate);
                if (!conn)
                {
                    listener.stop();
                    co_return;
                }
                const auto bnd = conn->bind_endpoint();
                const udp::endpoint bnd_ep(net::ip::make_address(bnd.host), bnd.port);

                udp::socket cudp(ioc.get_executor());
                cudp.open(udp::v4(), oec);
                cudp.bind(udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

                // 发一个数据报到黑洞目标（无回包）
                const auto frame = make_frame(
                    socks5::address{socks5::address_type::domain, "example.com", 53},
                    "to silent target");
                boost::system::error_code sock_ec;
                co_await cudp.async_send_to(
                    net::buffer(frame), bnd_ep, net::redirect_error(net::use_awaitable, sock_ec));

                // 等待超过 idle_timeout：TCP 控制连接应被服务端关闭（EOF/错误）。
                // 注意：不能把 ec != {} 当作关闭信号——等待超时赢时取消读也会置
                // operation_aborted，会让「未关闭」误判为「已关闭」（vacuously pass）。
                std::array<std::byte, 1> probe{};
                net::steady_timer wait(ioc);
                wait.expires_after(idle_to + std::chrono::milliseconds(400));
                auto rd = conn->async_read_some(std::span(probe), ec);
                auto wt = wait.async_wait(net::use_awaitable);
                using boost::asio::experimental::awaitable_operators::operator||;
                const auto res = co_await (std::move(rd) || std::move(wt));
                closed_by_idle = res.index() == 0;

                cudp.close();
                conn->close();
                listener.stop();
            });

        EXPECT_FALSE(watchdog_fired);
        EXPECT_TRUE(closed_by_idle);
    }
} // namespace
