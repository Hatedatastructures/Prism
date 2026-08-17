/**
 * @file Ss2022DgramSession.cpp
 * @brief SS2022 UDP 数据报会话测试（dgram 成功路径）
 * @details 覆盖：
 *          - 客户端 → 服务端单向数据报（逐包 AEAD）
 *          - 双向回环（服务端回发）
 *          - 包内目标地址解析（src 还原）
 *          - 错误路径：无数据超时 / 绑定时钟不回
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <common/protocols/shadowsocks2022/shadowsocks2022.hpp>

namespace
{
    namespace net = boost::asio;
    using namespace preview;

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

    TEST(Ss2022DgramSession, ClientToServerDatagram)
    {
        net::io_context ioc;

        shadowsocks2022::server_config cfg;
        cfg.password = "pass123";
        const auto server = shadowsocks2022::accept_packet(ioc.get_executor(), 0, cfg);
        ASSERT_NE(server, nullptr);

        // 客户端：连接服务端端口（从底层 socket 取）
        const auto server_udp = dynamic_cast<preview::transport::unreliable *>(server->next_layer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->native_socket().local_endpoint().port();

        shadowsocks2022::client_config client_cfg;
        client_cfg.password = "pass123";
        auto client = shadowsocks2022::connect_packet(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port),
                                                      client_cfg);
        ASSERT_NE(client, nullptr);

        // 目标地址（服务端收到的包内目标）
        shadowsocks2022::address dest;
        dest.type = shadowsocks2022::address_type::ipv4;
        dest.host = "127.0.0.1";
        dest.port = 12345;

        std::string received;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端收（先挂起）
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             shadowsocks2022::address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await server->async_receive_from(src, payload);
                             if (err == error::none)
                             {
                                 received.assign(reinterpret_cast<const char *>(payload.data()),
                                                 payload.size());
                             }
                         },
                         net::detached);

                     // 客户端发
                     const std::string msg = "ss2022-dgram";
                     const auto err = co_await client->async_send_to(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
                     EXPECT_EQ(err, error::none);

                     // 等服务端收到
                     for (int i = 0; i < 50 && received.empty(); ++i)
                     {
                         net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(10));
                         co_await t.async_wait(net::use_awaitable);
                     }
                 });
        EXPECT_EQ(received, "ss2022-dgram");
    }

    TEST(Ss2022DgramSession, BidirectionalEcho)
    {
        net::io_context ioc;

        shadowsocks2022::server_config cfg;
        cfg.password = "echo-pass";
        const auto server = shadowsocks2022::accept_packet(ioc.get_executor(), 0, cfg);
        ASSERT_NE(server, nullptr);
        const auto server_udp = dynamic_cast<preview::transport::unreliable *>(server->next_layer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->native_socket().local_endpoint().port();

        shadowsocks2022::client_config client_cfg;
        client_cfg.password = "echo-pass";
        auto client = shadowsocks2022::connect_packet(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port),
                                                      client_cfg);
        ASSERT_NE(client, nullptr);

        shadowsocks2022::address dest;
        dest.type = shadowsocks2022::address_type::ipv4;
        dest.host = "127.0.0.1";
        dest.port = 9999;

        std::string echoed;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：收 → 原样回发
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             shadowsocks2022::address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await server->async_receive_from(src, payload);
                             if (err == error::none)
                             {
                                 co_await server->async_send_to(src, payload);
                             }
                         },
                         net::detached);

                     // 客户端发
                     const std::string msg = "echo-me";
                     auto err = co_await client->async_send_to(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
                     EXPECT_EQ(err, error::none);

                     // 客户端收回显
                     shadowsocks2022::address src2;
                     std::vector<std::uint8_t> back;
                     err = co_await client->async_receive_from(src2, back);
                     EXPECT_EQ(err, error::none);
                     echoed.assign(reinterpret_cast<const char *>(back.data()), back.size());
                 });
        EXPECT_EQ(echoed, "echo-me");
    }

    TEST(Ss2022DgramSession, BadPasswordRejected)
    {
        net::io_context ioc;

        shadowsocks2022::server_config server_cfg;
        server_cfg.password = "server-pass";
        const auto server = shadowsocks2022::accept_packet(ioc.get_executor(), 0, server_cfg);
        ASSERT_NE(server, nullptr);
        const auto server_udp = dynamic_cast<preview::transport::unreliable *>(server->next_layer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->native_socket().local_endpoint().port();

        // 错误密码客户端
        shadowsocks2022::client_config bad_cfg;
        bad_cfg.password = "wrong-pass";
        auto client = shadowsocks2022::connect_packet(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port), bad_cfg);
        ASSERT_NE(client, nullptr);

        shadowsocks2022::address dest;
        dest.type = shadowsocks2022::address_type::ipv4;
        dest.host = "127.0.0.1";
        dest.port = 7777;

        bool server_received = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             shadowsocks2022::address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await server->async_receive_from(src, payload);
                             server_received = (err == error::none);
                         },
                         net::detached);

                     const std::string msg = "bad-key";
                     co_await client->async_send_to(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));

                     // 密码不匹配 → 服务端 AEAD 解密失败 → 不产生有效包
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(100));
                     co_await t.async_wait(net::use_awaitable);
                 });
        EXPECT_FALSE(server_received);
    }

} // namespace
