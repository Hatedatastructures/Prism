/**
 * @file SS2022UdpE2ETest.cpp
 * @brief Shadowsocks2022 UDP 直连测试（独立数据报通道）
 * @details 服务端统一 bind 端口 0 后回读实际端口，避免 ctest 并行冲突；
 *          所有接收操作与看门狗定时器竞速，回归时失败而非挂死。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <common/core/error.hpp>
#include <common/protocols/shadowsocks2022/shadowsocks2022.hpp>

namespace
{
    namespace net = boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace preview;

    /// 接收看门狗超时（超过即判定挂死）
    constexpr auto kRecvDeadline = std::chrono::milliseconds(2000);

    /**
     * @brief 与看门狗竞速的接收：返回 nullopt 表示超时（测试应判失败）
     */
    auto recv_guarded(const shadowsocks2022::shared_dgram &sock, shadowsocks2022::address &src,
                      std::vector<std::uint8_t> &rx)
        -> net::awaitable<std::optional<error>>
    {
        net::steady_timer wd(sock->executor());
        wd.expires_after(kRecvDeadline);
        auto result = co_await (sock->async_receive_from(src, rx) ||
                                wd.async_wait(net::use_awaitable));
        if (result.index() == 1)
        {
            co_return std::nullopt; // 超时
        }
        co_return std::get<0>(std::move(result));
    }

    /// 创建绑定随机端口的服务端并回读端点
    auto make_server(net::io_context &ioc, const char *password)
        -> std::pair<shadowsocks2022::shared_dgram, net::ip::udp::endpoint>
    {
        net::ip::udp::endpoint bound;
        auto server = shadowsocks2022::accept_packet(
            ioc.get_executor(), 0, shadowsocks2022::server_config{password}, &bound);
        return {std::move(server), bound};
    }

    TEST(SS2022Udp, DirectEchoDomain)
    {
        net::io_context ioc;
        bool ok = false;
        std::exception_ptr done_ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto [server, bound] = make_server(ioc, "secret");
            if (!server) { ADD_FAILURE() << "server null"; co_return; }
            const auto remote = "127.0.0.1:" + std::to_string(bound.port());
            auto client = shadowsocks2022::connect_packet(
                ioc.get_executor(), remote, shadowsocks2022::client_config{"secret"});
            if (!client) { ADD_FAILURE() << "client null"; co_return; }

            const std::string payload = "ss2022 udp payload";
            shadowsocks2022::address dst{shadowsocks2022::address_type::domain, "example.com", 443};
            auto serr = co_await client->async_send_to(
                dst, std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            if (serr != error::none) { ADD_FAILURE() << (int)serr; co_return; }

            shadowsocks2022::address src;
            std::vector<std::uint8_t> rx;
            const auto rerr = co_await recv_guarded(server, src, rx);
            if (rerr != error::none) { ADD_FAILURE() << "recv1: " << (rerr ? (int)*rerr : -1); co_return; }
            const std::string got(reinterpret_cast<const char *>(rx.data()), rx.size());
            if (got != payload) { ADD_FAILURE() << got; co_return; }

            auto serr2 = co_await server->async_send_to(
                src, std::span<const std::uint8_t>(rx.data(), rx.size()));
            if (serr2 != error::none) { ADD_FAILURE() << (int)serr2; co_return; }

            shadowsocks2022::address src2;
            std::vector<std::uint8_t> rx2;
            const auto rerr2 = co_await recv_guarded(client, src2, rx2);
            if (rerr2 != error::none) { ADD_FAILURE() << "recv2: " << (rerr2 ? (int)*rerr2 : -1); co_return; }
            const std::string echo(reinterpret_cast<const char *>(rx2.data()), rx2.size());
            ok = (echo == payload);
        }, [&](std::exception_ptr ep) { done_ep = ep; ioc.stop(); });
        ioc.run();
        if (done_ep)
        {
            std::rethrow_exception(done_ep);
        }
        EXPECT_TRUE(ok);
    }

    TEST(SS2022Udp, DirectEchoIpv4)
    {
        net::io_context ioc;
        bool ok = false;
        std::exception_ptr done_ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto [server, bound] = make_server(ioc, "secret");
            if (!server) { ADD_FAILURE() << "server null"; co_return; }
            const auto remote = "127.0.0.1:" + std::to_string(bound.port());
            auto client = shadowsocks2022::connect_packet(
                ioc.get_executor(), remote, shadowsocks2022::client_config{"secret"});
            if (!client) { ADD_FAILURE() << "client null"; co_return; }

            const std::string payload = "ipv4 payload";
            shadowsocks2022::address dst{shadowsocks2022::address_type::ipv4, "1.2.3.4", 80};
            auto serr = co_await client->async_send_to(
                dst, std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            if (serr != error::none) { ADD_FAILURE() << (int)serr; co_return; }
            shadowsocks2022::address src;
            std::vector<std::uint8_t> rx;
            const auto rerr = co_await recv_guarded(server, src, rx);
            if (rerr != error::none) { ADD_FAILURE() << "recv: " << (rerr ? (int)*rerr : -1); co_return; }
            ok = (std::string(reinterpret_cast<const char *>(rx.data()), rx.size()) == payload);
        }, [&](std::exception_ptr ep) { done_ep = ep; ioc.stop(); });
        ioc.run();
        if (done_ep)
        {
            std::rethrow_exception(done_ep);
        }
        EXPECT_TRUE(ok);
    }

    TEST(SS2022Udp, BadPskDrop)
    {
        net::io_context ioc;
        bool rejected = false;
        std::exception_ptr done_ep;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto [server, bound] = make_server(ioc, "right");
            if (!server) { ADD_FAILURE() << "server null"; co_return; }
            const auto remote = "127.0.0.1:" + std::to_string(bound.port());
            auto client = shadowsocks2022::connect_packet(
                ioc.get_executor(), remote, shadowsocks2022::client_config{"wrong"});
            if (!client) { ADD_FAILURE() << "client null"; co_return; }

            const std::string payload = "bad psk";
            shadowsocks2022::address dst{shadowsocks2022::address_type::domain, "example.com", 443};
            auto serr = co_await client->async_send_to(
                dst, std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
            if (serr != error::none) { ADD_FAILURE() << (int)serr; co_return; }

            // 错误 PSK 包必须被拒绝：SessionID 校验失败 → bad_auth，且不产出可读回包。
            // dgram 为无状态逐包解析，坏包以错误码上浮（对齐 codec parse_udp_packet 契约）
            shadowsocks2022::address src;
            std::vector<std::uint8_t> rx;
            const auto rerr = co_await recv_guarded(server, src, rx);
            if (rerr != error::bad_auth)
            {
                ADD_FAILURE() << "expected bad_auth, got "
                              << (rerr ? (int)*rerr : -1);
                co_return;
            }
            // 关闭后接收应以错误收口而非挂死
            server->close();
            const auto cerr2 = co_await server->async_receive_from(src, rx);
            rejected = (cerr2 != error::none);
        }, [&](std::exception_ptr ep) { done_ep = ep; ioc.stop(); });
        ioc.run();
        if (done_ep)
        {
            std::rethrow_exception(done_ep);
        }
        EXPECT_TRUE(rejected);
    }
}
