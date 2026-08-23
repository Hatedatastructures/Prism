/**
 * @file ListenerE2ETest.cpp
 * @brief TCP listener 骨架测试（T4-3）
 * @details 覆盖：
 *          - 亲和性分发：同 key 稳定 / 分布均匀
 *          - 全链路 E2E：client → listener → 会话识别 → dial → echo 上游 → 回显
 *          - stop 后不再接受连接
 *          - 连接风暴：并发多连接全部 echo 成功
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include <common/core/fault/code.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

    // 公共样板（run_coro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::tcp_echo_server;
    using psm::testing::run_coro;

    /// 构造可识别首包（socks5 greeting）
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    TEST(AffinityBalancer, StableAndUniform)
    {
        preview::runtime::affinity_balancer balancer(4);
        // 相同 key 稳定
        EXPECT_EQ(balancer.select("1.2.3.4"), balancer.select("1.2.3.4"));
        EXPECT_EQ(balancer.select("10.0.0.1"), balancer.select("10.0.0.1"));
        // 分布覆盖全部 worker
        std::array<std::size_t, 4> buckets{};
        for (int i = 1; i <= 64; ++i)
        {
            ++buckets[balancer.select("192.168.0." + std::to_string(i))];
        }
        for (const auto b : buckets)
        {
            EXPECT_GT(b, 0);
        }
        // 单 worker 恒为 0
        preview::runtime::affinity_balancer single(1);
        EXPECT_EQ(single.select("any"), 0);
    }

    TEST(TcpListener, FullChainE2E)
    {
        net::io_context ioc;

        // 真实 echo 上游
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor.async_accept(
                        net::redirect_error(net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    net::co_spawn(ioc.get_executor(), tcp_echo_server(std::move(sock)), net::detached);
                }
            },
            net::detached);

        // listener：会话（识别 socks5 + dial 到 echo 上游）
        preview::runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](preview::shared_transmission inbound, std::size_t) -> std::shared_ptr<preview::runtime::session>
            {
                preview::runtime::session_options opts;
                opts.relay_idle_timeout = std::chrono::milliseconds(200);
                opts.prepare = [](const preview::recognition::recognize_result &,
                                  preview::middleware::context &ctx) -> net::awaitable<preview::fault::code>
                {
                    ctx.target.positive = true;
                    ctx.target.host = "127.0.0.1";
                    ctx.target.port = "0"; // 由 dial 捕获端口替换
                    co_return preview::fault::code::success;
                };
                opts.dial = [&](const preview::network::target &t) -> net::awaitable<
                    std::pair<preview::fault::code, preview::shared_transmission>>
                {
                    std::error_code ec;
                    preview::network::dialer::dialer d(ioc.get_executor());
                    auto conn = co_await d.connect("127.0.0.1", echo_port, ec);
                    if (ec)
                    {
                        co_return std::pair{preview::fault::code::unreachable, nullptr};
                    }
                    co_return std::pair{preview::fault::code::success, std::move(conn)};
                };
                return std::make_shared<preview::runtime::session>(std::move(opts));
            },
            2);

        // 单 run_coro：start + 客户端流程（避免 ioc.stop() 杀死挂起协程）
        std::string echo_back;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto start_rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                     EXPECT_EQ(start_rc, preview::fault::code::success);
                     const auto listen_port = listener.local_endpoint().port();

                     std::error_code ec;
                     preview::network::dialer::dialer d(ioc.get_executor());
                     auto conn = co_await d.connect("127.0.0.1", listen_port, ec);
                     if (ec || !conn)
                     {
                         co_return;
                     }
                     const auto payload = socks5_greeting();
                     co_await conn->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await conn->async_read_some(buf, ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                     conn->close();
                     listener.stop();
                 });
        EXPECT_EQ(echo_back, socks5_greeting());
    }

    TEST(TcpListener, StopStopsAccepting)
    {
        net::io_context ioc;
        preview::runtime::tcp_listener listener(
            ioc.get_executor(),
            [](preview::shared_transmission, std::size_t) -> std::shared_ptr<preview::runtime::session>
            { return nullptr; });

        preview::fault::code start_rc = preview::fault::code::success;
        bool connected = false;
        bool refused = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     start_rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                     const auto listen_port = listener.local_endpoint().port();

                     // 首次连接成功（accept 循环工作）
                     std::error_code ec;
                     preview::network::dialer::dialer d(ioc.get_executor());
                     auto conn = co_await d.connect("127.0.0.1", listen_port, ec);
                     connected = !ec;
                     if (conn)
                     {
                         conn->close();
                     }

                     // 停止后连接被拒绝
                     listener.stop();
                     std::error_code ec2;
                     auto conn2 = co_await d.connect("127.0.0.1", listen_port, ec2);
                     refused = ec2 || conn2 == nullptr;
                     if (conn2)
                     {
                         conn2->close();
                     }
                 });
        EXPECT_EQ(start_rc, preview::fault::code::success);
        EXPECT_TRUE(connected);
        EXPECT_TRUE(refused);
    }

    TEST(TcpListener, ConnectionStorm)
    {
        net::io_context ioc;

        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_acceptor.local_endpoint().port();
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor.async_accept(
                        net::redirect_error(net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    net::co_spawn(ioc.get_executor(), tcp_echo_server(std::move(sock)), net::detached);
                }
            },
            net::detached);

        constexpr int conn_count = 20;
        preview::runtime::tcp_listener listener(
            ioc.get_executor(),
            [&](preview::shared_transmission, std::size_t) -> std::shared_ptr<preview::runtime::session>
            {
                preview::runtime::session_options opts;
                opts.relay_idle_timeout = std::chrono::milliseconds(300);
                opts.prepare = [](const preview::recognition::recognize_result &,
                                  preview::middleware::context &ctx) -> net::awaitable<preview::fault::code>
                {
                    ctx.target.positive = true;
                    ctx.target.host = "127.0.0.1";
                    ctx.target.port = "0";
                    co_return preview::fault::code::success;
                };
                opts.dial = [&](const preview::network::target &) -> net::awaitable<
                    std::pair<preview::fault::code, preview::shared_transmission>>
                {
                    std::error_code ec;
                    preview::network::dialer::dialer d(ioc.get_executor());
                    auto conn = co_await d.connect("127.0.0.1", echo_port, ec);
                    if (ec)
                    {
                        co_return std::pair{preview::fault::code::unreachable, nullptr};
                    }
                    co_return std::pair{preview::fault::code::success, std::move(conn)};
                };
                return std::make_shared<preview::runtime::session>(std::move(opts));
            },
            4);

        preview::fault::code start_rc = preview::fault::code::success;
        // 并发连接：全部 echo 成功
        int success = 0;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     start_rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
                     const auto listen_port = listener.local_endpoint().port();

                     std::atomic<int> done{0};
                     const auto payload = socks5_greeting();
                     for (int i = 0; i < conn_count; ++i)
                     {
                         net::co_spawn(
                             ioc.get_executor(),
                             [&, i]() -> net::awaitable<void>
                             {
                                 std::error_code ec;
                                 preview::network::dialer::dialer d(ioc.get_executor());
                                 auto conn = co_await d.connect("127.0.0.1", listen_port, ec);
                                 if (ec)
                                 {
                                     ++done;
                                     co_return;
                                 }
                                 co_await conn->async_write_some(
                                     std::span<const std::byte>(
                                         reinterpret_cast<const std::byte *>(payload.data()),
                                         payload.size()),
                                     ec);
                                 std::array<std::byte, 64> buf{};
                                 const auto n = co_await conn->async_read_some(buf, ec);
                                 if (!ec && std::string_view(reinterpret_cast<const char *>(buf.data()), n) ==
                                                payload)
                                 {
                                     ++success;
                                 }
                                 conn->close();
                                 ++done;
                             },
                             net::detached);
                     }
                     while (done < conn_count)
                     {
                         net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(10));
                         co_await t.async_wait(net::use_awaitable);
                     }
                     listener.stop();
                 });
        EXPECT_EQ(start_rc, preview::fault::code::success);
        EXPECT_EQ(success, conn_count);
    }

} // namespace
