/**
 * @file OutboundTest.cpp
 * @brief 出站拨号实验测试。
 * @details 覆盖反向路由拨号、直接目标拨号和非法端口拒绝。
 */

#include <Experiments/Prism/Net/Outbound/Outbound.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Prism::SharedTransmission;

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

    auto StartAccept(Net::io_context &Ioc, Net::ip::tcp::acceptor &Acceptor) -> void
    {
        Net::co_spawn(
            Ioc.get_executor(),
            [&Acceptor]() -> Net::awaitable<void>
            {
                auto Sock = co_await Acceptor.async_accept(Net::use_awaitable);
                Sock.close();
            },
            Net::detached);
    }

    TEST(Outbound, DialViaReverseRoute)
    {
        Net::io_context ioc;
        Net::ip::tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto real_port = acceptor.local_endpoint().port();

        auto routes = std::make_shared<Prism::Experiments::Routing::RouteTable>();
        routes->AddReverse("internal.example", Prism::Experiments::Routing::Endpoint{"127.0.0.1", real_port});

        std::error_code ec;
        SharedTransmission Conn;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     StartAccept(ioc, acceptor);
                     Prism::Experiments::Outbound::Outbound ob(ioc.get_executor(), routes);
                     Conn = co_await ob.Dial(Prism::Experiments::Outbound::Target{"internal.example", 9999}, ec);
                 });
        EXPECT_FALSE(ec);
        EXPECT_NE(Conn, nullptr);
    }

    TEST(Outbound, DialDirectTarget)
    {
        Net::io_context ioc;
        Net::ip::tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto port = acceptor.local_endpoint().port();

        auto routes = std::make_shared<Prism::Experiments::Routing::RouteTable>();
        std::error_code ec;
        SharedTransmission Conn;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     StartAccept(ioc, acceptor);
                     Prism::Experiments::Outbound::Outbound ob(ioc.get_executor(), routes);
                     Conn = co_await ob.Dial(Prism::Experiments::Outbound::Target{"127.0.0.1", port}, ec);
                 });
        EXPECT_FALSE(ec);
        EXPECT_NE(Conn, nullptr);
    }

    TEST(Outbound, InvalidPortRejected)
    {
        Net::io_context ioc;
        auto routes = std::make_shared<Prism::Experiments::Routing::RouteTable>();
        std::error_code ec;
        SharedTransmission Conn;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Prism::Experiments::Outbound::Outbound ob(ioc.get_executor(), routes);
                     Conn = co_await ob.Dial(Prism::Experiments::Outbound::Target{"127.0.0.1", 0}, ec);
                 });
        EXPECT_TRUE(ec);
        EXPECT_EQ(Conn, nullptr);
    }
} // namespace
