/**
 * @file DialE2ETest.cpp
 * @brief outbound::dial 离线端到端（回环 echo / 确定性拒绝端口）
 * @details 全程不依赖外部网络与 DNS：正向场景经回环 echo 验证数据面；
 *          失败场景用"绑定即关闭的监听端口"制造确定性 connection_refused。
 */

#include <gtest/gtest.h>

#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/outbound/dial.hpp>
#include <prism/net/connection/outbound/direct.hpp>
#include <prism/net/connection/route/table.hpp>
#include <prism/net/connection/target.hpp>
#include <prism/user/stats/traffic.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace {

    /// 驱动协程直至完成（异常透传）
    auto run_coro(net::io_context &ioc, auto coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 单次 echo：接受一个连接，读到的数据原样写回后关闭
    auto echo_once(tcp::acceptor &acc) -> net::awaitable<void>
    {
        tcp::socket sock = co_await acc.async_accept(net::use_awaitable);
        std::array<std::byte, 512> buf{};
        boost::system::error_code ec;
        const auto n = co_await sock.async_read_some(
            net::buffer(buf), net::redirect_error(net::use_awaitable, ec));
        if (!ec && n > 0)
        {
            co_await net::async_write(sock, net::buffer(buf.data(), n),
                                      net::redirect_error(net::use_awaitable, ec));
        }
        sock.close(ec);
    }

    TEST(OutboundDialE2E, DirectEchoRoundtrip)
    {
        net::io_context ioc;
        tcp::acceptor acc(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        const auto port = acc.local_endpoint().port();
        bool echoed = false;

        auto body = [&]() -> net::awaitable<void>
        {
            net::co_spawn(ioc, echo_once(acc), net::detached);

            psm::connect::dialer dlr(
                psm::connect::dialer_options{ioc, {}, std::chrono::milliseconds(2000)});
            psm::outbound::direct out(dlr);
            psm::stats::traffic::traffic_state traffic;
            psm::outbound::dial_handles handles{out, ioc, traffic};

            psm::connect::target tg;
            tg.host = "127.0.0.1";
            tg.port = std::to_string(port);
            tg.positive = true;
            const auto r =
                co_await psm::outbound::dial(handles, tg, psm::outbound::dial_options{});
            // 协程内禁用 ASSERT_*（宏展开的普通 return 在协程中不合法）：
            // EXPECT 记录失败后 co_return 收口，避免空指针解引用
            EXPECT_EQ(r.code, psm::fault::code::success);
            EXPECT_NE(r.transport, nullptr);
            if (r.code != psm::fault::code::success || r.transport == nullptr)
            {
                co_return;
            }
            // 回环拨号可快于时钟粒度（elapsed 为 0 合法），仅要求未倒流
            EXPECT_GE(r.elapsed.count(), 0);

            // 数据面验证：经拨号建立的传输完成一次往返
            const std::array<std::byte, 8> payload = {
                std::byte{0xD1}, std::byte{0xD2}, std::byte{0xD3}, std::byte{0xD4},
                std::byte{0xD5}, std::byte{0xD6}, std::byte{0xD7}, std::byte{0xD8}};
            std::error_code wec;
            co_await psm::transport::async_write(*r.transport,
                                                 std::span<const std::byte>(payload), wec);
            EXPECT_FALSE(wec);
            std::array<std::byte, 8> rx{};
            std::error_code rec;
            const auto n = co_await r.transport->async_read_some(std::span<std::byte>(rx), rec);
            EXPECT_FALSE(rec);
            echoed = !wec && !rec &&
                     std::equal(payload.begin(), payload.end(), rx.begin()) && n == payload.size();
            r.transport->close();
        };
        run_coro(ioc, body());

        EXPECT_TRUE(echoed);
    }

    TEST(OutboundDialE2E, ConnectRefused)
    {
        net::io_context ioc;

        auto body = [&]() -> net::awaitable<void>
        {
            // 制造确定性拒绝端口：先取得空闲端口再关闭监听
            std::uint16_t dead_port = 0;
            {
                tcp::acceptor acc(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
                dead_port = acc.local_endpoint().port();
                boost::system::error_code ec;
                acc.close(ec);
            }

            psm::connect::dialer dlr(
                psm::connect::dialer_options{ioc, {}, std::chrono::milliseconds(2000)});
            psm::outbound::direct out(dlr);
            psm::stats::traffic::traffic_state traffic;
            psm::outbound::dial_handles handles{out, ioc, traffic};

            psm::connect::target tg;
            tg.host = "127.0.0.1";
            tg.port = std::to_string(dead_port);
            tg.positive = true;
            const auto r =
                co_await psm::outbound::dial(handles, tg, psm::outbound::dial_options{});
            EXPECT_NE(r.code, psm::fault::code::success);
            EXPECT_EQ(r.transport, nullptr);
        };
        run_coro(ioc, body());
    }

    TEST(OutboundDialE2E, EmptyRouteTableMisses)
    {
        psm::connect::route_table t;
        EXPECT_FALSE(t.lookup("example.com"));
        EXPECT_FALSE(t.lookup("8.8.8.8"));
    }
}
