/**
 * @file DialerTest.cpp
 * @brief TCP 拨号测试（T3-1）
 * @details 覆盖：
 *          - 成功连接（loopback）
 *          - 连接拒绝（未监听端口）
 *          - 超时（不可达地址）
 *          - 无效端口 / IPv6 禁用
 */

#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Transport/Reliable.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Preview::SharedTransmission;

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error)
                      { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
} // namespace

TEST(Dialer, ConnectSuccess)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    SharedTransmission Conn;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> Net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(Net::use_awaitable);
                         sock.close();
                     },
                     Net::detached);
                 Preview::Network::Dialer::Dialer d(ioc.get_executor());
                 Conn = co_await d.Connect("127.0.0.1", port, ec);
             });
    EXPECT_FALSE(ec);
    ASSERT_NE(Conn, nullptr);
}

TEST(Dialer, ConnectRefused)
{
    Net::io_context ioc;
    // 找一个未监听端口
    Tcp::acceptor Probe(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = Probe.local_endpoint().port();
    Probe.close();

    std::error_code ec;
    SharedTransmission Conn;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Preview::Network::Dialer::Dialer d(ioc.get_executor());
                 Conn = co_await d.Connect("127.0.0.1", port, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(Conn, nullptr);
}

TEST(Dialer, ConnectTimeout)
{
    Net::io_context ioc;
    std::error_code ec;
    SharedTransmission Conn;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Preview::Network::Dialer::DialOptions opts;
                 opts.Timeout = std::chrono::milliseconds(100);
                 Preview::Network::Dialer::Dialer d(ioc.get_executor(), opts);
                 // 不可达地址（TEST-NET 保留段）
                 Conn = co_await d.Connect("192.0.2.1", 8080, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(Conn, nullptr);
}

TEST(Dialer, InvalidPortZero)
{
    Net::io_context ioc;
    std::error_code ec;
    SharedTransmission Conn;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Preview::Network::Dialer::Dialer d(ioc.get_executor());
                 Conn = co_await d.Connect("127.0.0.1", 0, ec);
             });
    // 端口 0 → 连接失败（系统随机端口无监听）
    EXPECT_TRUE(ec || Conn == nullptr);
}

TEST(Dialer, Ipv6Disabled)
{
    Net::io_context ioc;
    std::error_code ec;
    SharedTransmission Conn;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Preview::Network::Dialer::DialOptions opts;
                 opts.EnableIpv6 = false;
                 Preview::Network::Dialer::Dialer d(ioc.get_executor(), opts);
                 Conn = co_await d.Connect("::1", 8080, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(Conn, nullptr);
}

TEST(Dialer, ConnectEchoTransfer)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::error_code ec;
    SharedTransmission Conn;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 Net::co_spawn(
                     ioc.get_executor(),
                     [&]() -> Net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(Net::use_awaitable);
                         // echo 一次
                         std::array<std::byte, 64> buf{};
                         boost::system::error_code r_ec;
                         const auto n = co_await sock.async_read_some(Net::buffer(buf), Net::redirect_error(Net::use_awaitable, r_ec));
                         if (n > 0)
                         {
                             co_await sock.async_write_some(Net::buffer(buf, n), Net::redirect_error(Net::use_awaitable, r_ec));
                         }
                         sock.close();
                     },
                     Net::detached);
                 Preview::Network::Dialer::Dialer d(ioc.get_executor());
                 Conn = co_await d.Connect("127.0.0.1", port, ec);
             });
    ASSERT_NE(Conn, nullptr);

    // echo 数据往返
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 const std::string msg = "Dialer-echo";
                 std::error_code w_ec;
                 co_await Conn->async_write_some(
                     std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()), msg.size()),
                     w_ec);
                 std::array<std::byte, 64> buf{};
                 std::error_code r_ec;
                 const auto n = co_await Conn->async_read_some(buf, r_ec);
                 EXPECT_EQ(n, msg.size());
                 EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), msg);
             });
}
