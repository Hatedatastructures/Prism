/**
 * @file RouteOutboundTest.cpp
 * @brief 路由表与出站拨号测试（T3-2）
 * @details 覆盖：
 *          - RouteTable：反向映射/正向端点/未命中/大小/清空
 *          - Outbound：路由解析 + 拨号（反向命中 → 映射端点）
 */

#include <preview/Net/Outbound/Outbound.hpp>
#include <preview/Net/Route/Route.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;

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

// ── RouteTable ──

TEST(RouteTable, ReverseMatch)
{
    Preview::Network::Route::RouteTable routes;
    routes.AddReverse("internal.example", Preview::Network::Route::Endpoint{"10.0.0.1", 8080});
    EXPECT_TRUE(routes.IsReverse("internal.example"));
    EXPECT_FALSE(routes.IsReverse("other.example"));
    const auto r = routes.Lookup("internal.example");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->Host, "10.0.0.1");
    EXPECT_EQ(r->Port, 8080u);
}

TEST(RouteTable, PositiveFallback)
{
    Preview::Network::Route::RouteTable routes;
    routes.SetPositive(Preview::Network::Route::Endpoint{"127.0.0.1", 443});
    // 未命中反向 → 正向
    const auto r = routes.Lookup("any.example");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->Host, "127.0.0.1");
    EXPECT_EQ(r->Port, 443u);
}

TEST(RouteTable, NoMatchNoPositive)
{
    Preview::Network::Route::RouteTable routes;
    EXPECT_FALSE(routes.Lookup("unknown").has_value());
}

TEST(RouteTable, SizeAndClear)
{
    Preview::Network::Route::RouteTable routes;
    routes.AddReverse("a", Preview::Network::Route::Endpoint{"1.1.1.1", 1});
    routes.AddReverse("b", Preview::Network::Route::Endpoint{"2.2.2.2", 2});
    EXPECT_EQ(routes.Size(), 2u);
    routes.Clear();
    EXPECT_EQ(routes.Size(), 0u);
    EXPECT_FALSE(routes.Lookup("a").has_value());
}

// ── Outbound ──

TEST(Outbound, DialViaReverseRoute)
{
    net::io_context ioc;
    net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    const auto real_port = acceptor.local_endpoint().port();

    auto routes = std::make_shared<Preview::Network::Route::RouteTable>();
    // 反向映射：internal.example → 本机 echo 端口
    routes->AddReverse("internal.example", Preview::Network::Route::Endpoint{"127.0.0.1", real_port});

    std::error_code ec;
    SharedTransmission Conn;
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
                 Preview::Network::Outbound::Outbound ob(ioc.get_executor(), routes);
                 Conn = co_await ob.Dial(Preview::Network::Outbound::Target{"internal.example", 9999}, ec);
             });
    // 反向路由命中 → 连接到映射端点（real_port）
    EXPECT_FALSE(ec);
    EXPECT_NE(Conn, nullptr);
}

TEST(Outbound, DialDirectTarget)
{
    net::io_context ioc;
    net::ip::tcp::acceptor acceptor(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    auto routes = std::make_shared<Preview::Network::Route::RouteTable>();
    std::error_code ec;
    SharedTransmission Conn;
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
                 Preview::Network::Outbound::Outbound ob(ioc.get_executor(), routes);
                 Conn = co_await ob.Dial(Preview::Network::Outbound::Target{"127.0.0.1", port}, ec);
             });
    EXPECT_FALSE(ec);
    EXPECT_NE(Conn, nullptr);
}

TEST(Outbound, InvalidPortRejected)
{
    net::io_context ioc;
    auto routes = std::make_shared<Preview::Network::Route::RouteTable>();
    std::error_code ec;
    SharedTransmission Conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 Preview::Network::Outbound::Outbound ob(ioc.get_executor(), routes);
                 Conn = co_await ob.Dial(Preview::Network::Outbound::Target{"127.0.0.1", 0}, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(Conn, nullptr);
}
