/**
 * @file DialerTest.cpp
 * @brief TCP 拨号测试（T3-1）
 * @details 覆盖：
 *          - 成功连接（loopback）
 *          - 连接拒绝（未监听端口）
 *          - 超时（不可达地址）
 *          - 无效端口 / IPv6 禁用
 */

#include <common/core/net/dialer/dialer.hpp>
#include <common/core/transport/reliable.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

    template <typename A>
    void run_coro(net::io_context &ioc, A coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
} // namespace

TEST(Dialer, ConnectSuccess)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    shared_transmission conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         sock.close();
                     },
                     net::detached);
                 preview::network::dialer::dialer d(ioc.get_executor());
                 conn = co_await d.connect("127.0.0.1", port, ec);
             });
    EXPECT_FALSE(ec);
    ASSERT_NE(conn, nullptr);
}

TEST(Dialer, ConnectRefused)
{
    net::io_context ioc;
    // 找一个未监听端口
    tcp::acceptor probe(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = probe.local_endpoint().port();
    probe.close();

    std::error_code ec;
    shared_transmission conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 preview::network::dialer::dialer d(ioc.get_executor());
                 conn = co_await d.connect("127.0.0.1", port, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(conn, nullptr);
}

TEST(Dialer, ConnectTimeout)
{
    net::io_context ioc;
    std::error_code ec;
    shared_transmission conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 preview::network::dialer::dial_options opts;
                 opts.timeout = std::chrono::milliseconds(100);
                 preview::network::dialer::dialer d(ioc.get_executor(), opts);
                 // 不可达地址（TEST-NET 保留段）
                 conn = co_await d.connect("192.0.2.1", 8080, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(conn, nullptr);
}

TEST(Dialer, InvalidPortZero)
{
    net::io_context ioc;
    std::error_code ec;
    shared_transmission conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 preview::network::dialer::dialer d(ioc.get_executor());
                 conn = co_await d.connect("127.0.0.1", 0, ec);
             });
    // 端口 0 → 连接失败（系统随机端口无监听）
    EXPECT_TRUE(ec || conn == nullptr);
}

TEST(Dialer, Ipv6Disabled)
{
    net::io_context ioc;
    std::error_code ec;
    shared_transmission conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 preview::network::dialer::dial_options opts;
                 opts.enable_ipv6 = false;
                 preview::network::dialer::dialer d(ioc.get_executor(), opts);
                 conn = co_await d.connect("::1", 8080, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(conn, nullptr);
}

TEST(Dialer, ConnectEchoTransfer)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    shared_transmission conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         // echo 一次
                         std::array<std::byte, 64> buf{};
                         boost::system::error_code r_ec;
                         const auto n = co_await sock.async_read_some(net::buffer(buf), net::redirect_error(net::use_awaitable, r_ec));
                         if (n > 0)
                         {
                             co_await sock.async_write_some(net::buffer(buf, n), net::redirect_error(net::use_awaitable, r_ec));
                         }
                         sock.close();
                     },
                     net::detached);
                 preview::network::dialer::dialer d(ioc.get_executor());
                 conn = co_await d.connect("127.0.0.1", port, ec);
             });
    ASSERT_NE(conn, nullptr);

    // echo 数据往返
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 const std::string msg = "dialer-echo";
                 std::error_code w_ec;
                 co_await conn->async_write_some(
                     std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()), msg.size()),
                     w_ec);
                 std::array<std::byte, 64> buf{};
                 std::error_code r_ec;
                 const auto n = co_await conn->async_read_some(buf, r_ec);
                 EXPECT_EQ(n, msg.size());
                 EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), msg);
             });
}
