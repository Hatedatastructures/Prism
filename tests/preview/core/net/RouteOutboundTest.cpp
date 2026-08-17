/**
 * @file RouteOutboundTest.cpp
 * @brief 路由表与出站拨号测试（T3-2）
 * @details 覆盖：
 *          - route_table：反向映射/正向端点/未命中/大小/清空
 *          - outbound：路由解析 + 拨号（反向命中 → 映射端点）
 */

#include <common/core/net/outbound/outbound.hpp>
#include <common/core/net/route/route.hpp>

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

// ── route_table ──

TEST(RouteTable, ReverseMatch)
{
    preview::network::route::route_table routes;
    routes.add_reverse("internal.example", preview::network::route::endpoint{"10.0.0.1", 8080});
    EXPECT_TRUE(routes.is_reverse("internal.example"));
    EXPECT_FALSE(routes.is_reverse("other.example"));
    const auto r = routes.lookup("internal.example");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "10.0.0.1");
    EXPECT_EQ(r->port, 8080u);
}

TEST(RouteTable, PositiveFallback)
{
    preview::network::route::route_table routes;
    routes.set_positive(preview::network::route::endpoint{"127.0.0.1", 443});
    // 未命中反向 → 正向
    const auto r = routes.lookup("any.example");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "127.0.0.1");
    EXPECT_EQ(r->port, 443u);
}

TEST(RouteTable, NoMatchNoPositive)
{
    preview::network::route::route_table routes;
    EXPECT_FALSE(routes.lookup("unknown").has_value());
}

TEST(RouteTable, SizeAndClear)
{
    preview::network::route::route_table routes;
    routes.add_reverse("a", preview::network::route::endpoint{"1.1.1.1", 1});
    routes.add_reverse("b", preview::network::route::endpoint{"2.2.2.2", 2});
    EXPECT_EQ(routes.size(), 2u);
    routes.clear();
    EXPECT_EQ(routes.size(), 0u);
    EXPECT_FALSE(routes.lookup("a").has_value());
}

// ── outbound ──

TEST(Outbound, DialViaReverseRoute)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto real_port = acceptor.local_endpoint().port();

    auto routes = std::make_shared<preview::network::route::route_table>();
    // 反向映射：internal.example → 本机 echo 端口
    routes->add_reverse("internal.example", preview::network::route::endpoint{"127.0.0.1", real_port});

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
                 preview::network::outbound::outbound ob(ioc.get_executor(), routes);
                 conn = co_await ob.dial(preview::network::outbound::target{"internal.example", 9999}, ec);
             });
    // 反向路由命中 → 连接到映射端点（real_port）
    EXPECT_FALSE(ec);
    EXPECT_NE(conn, nullptr);
}

TEST(Outbound, DialDirectTarget)
{
    net::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    auto routes = std::make_shared<preview::network::route::route_table>();
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
                 preview::network::outbound::outbound ob(ioc.get_executor(), routes);
                 conn = co_await ob.dial(preview::network::outbound::target{"127.0.0.1", port}, ec);
             });
    EXPECT_FALSE(ec);
    EXPECT_NE(conn, nullptr);
}

TEST(Outbound, InvalidPortRejected)
{
    net::io_context ioc;
    auto routes = std::make_shared<preview::network::route::route_table>();
    std::error_code ec;
    shared_transmission conn;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 preview::network::outbound::outbound ob(ioc.get_executor(), routes);
                 conn = co_await ob.dial(preview::network::outbound::target{"127.0.0.1", 0}, ec);
             });
    EXPECT_TRUE(ec);
    EXPECT_EQ(conn, nullptr);
}
