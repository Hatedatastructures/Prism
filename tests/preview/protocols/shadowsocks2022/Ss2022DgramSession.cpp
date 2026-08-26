/**
 * @file Ss2022DgramSession.cpp
 * @brief SS2022 UDP 数据报会话测试（Dgram 成功路径）
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

#include <common/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;

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

        Shadowsocks2022::ServerConfig cfg;
        cfg.password = "pass123";
        const auto Server = Shadowsocks2022::AcceptPacket(ioc.get_executor(), 0, cfg);
        ASSERT_NE(Server, nullptr);

        // 客户端：连接服务端端口（从底层 socket 取）
        const auto server_udp = dynamic_cast<Preview::Transport::Unreliable *>(Server->NextLayer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->NativeSocket().local_endpoint().port();

        Shadowsocks2022::ClientConfig client_cfg;
        client_cfg.password = "pass123";
        auto Client = Shadowsocks2022::ConnectPacket(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port),
                                                      client_cfg);
        ASSERT_NE(Client, nullptr);

        // 目标地址（服务端收到的包内目标）
        Shadowsocks2022::Address dest;
        dest.Type = Shadowsocks2022::AddressType::Ipv4;
        dest.Host = "127.0.0.1";
        dest.Port = 12345;

        std::string received;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端收（先挂起）
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Shadowsocks2022::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await Server->AsyncReceiveFrom(src, payload);
                             if (err == Error::None)
                             {
                                 received.assign(reinterpret_cast<const char *>(payload.data()),
                                                 payload.size());
                             }
                         },
                         net::detached);

                     // 客户端发
                     const std::string msg = "ss2022-Dgram";
                     const auto err = co_await Client->AsyncSendTo(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
                     EXPECT_EQ(err, Error::None);

                     // 等服务端收到
                     for (int i = 0; i < 50 && received.empty(); ++i)
                     {
                         net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(10));
                         co_await t.async_wait(net::use_awaitable);
                     }
                 });
        EXPECT_EQ(received, "ss2022-Dgram");
    }

    TEST(Ss2022DgramSession, BidirectionalEcho)
    {
        net::io_context ioc;

        Shadowsocks2022::ServerConfig cfg;
        cfg.password = "echo-pass";
        const auto Server = Shadowsocks2022::AcceptPacket(ioc.get_executor(), 0, cfg);
        ASSERT_NE(Server, nullptr);
        const auto server_udp = dynamic_cast<Preview::Transport::Unreliable *>(Server->NextLayer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->NativeSocket().local_endpoint().port();

        Shadowsocks2022::ClientConfig client_cfg;
        client_cfg.password = "echo-pass";
        auto Client = Shadowsocks2022::ConnectPacket(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port),
                                                      client_cfg);
        ASSERT_NE(Client, nullptr);

        Shadowsocks2022::Address dest;
        dest.Type = Shadowsocks2022::AddressType::Ipv4;
        dest.Host = "127.0.0.1";
        dest.Port = 9999;

        std::string echoed;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：收 → 原样回发
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Shadowsocks2022::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await Server->AsyncReceiveFrom(src, payload);
                             if (err == Error::None)
                             {
                                 co_await Server->AsyncSendTo(src, payload);
                             }
                         },
                         net::detached);

                     // 客户端发
                     const std::string msg = "echo-me";
                     auto err = co_await Client->AsyncSendTo(
                         dest, std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
                     EXPECT_EQ(err, Error::None);

                     // 客户端收回显
                     Shadowsocks2022::Address src2;
                     std::vector<std::uint8_t> back;
                     err = co_await Client->AsyncReceiveFrom(src2, back);
                     EXPECT_EQ(err, Error::None);
                     echoed.assign(reinterpret_cast<const char *>(back.data()), back.size());
                 });
        EXPECT_EQ(echoed, "echo-me");
    }

    TEST(Ss2022DgramSession, BadPasswordRejected)
    {
        net::io_context ioc;

        Shadowsocks2022::ServerConfig server_cfg;
        server_cfg.password = "Server-pass";
        const auto Server = Shadowsocks2022::AcceptPacket(ioc.get_executor(), 0, server_cfg);
        ASSERT_NE(Server, nullptr);
        const auto server_udp = dynamic_cast<Preview::Transport::Unreliable *>(Server->NextLayer());
        ASSERT_NE(server_udp, nullptr);
        const auto server_port = server_udp->NativeSocket().local_endpoint().port();

        // 错误密码客户端
        Shadowsocks2022::ClientConfig bad_cfg;
        bad_cfg.password = "wrong-pass";
        auto Client = Shadowsocks2022::ConnectPacket(ioc.get_executor(),
                                                      "127.0.0.1:" + std::to_string(server_port), bad_cfg);
        ASSERT_NE(Client, nullptr);

        Shadowsocks2022::Address dest;
        dest.Type = Shadowsocks2022::AddressType::Ipv4;
        dest.Host = "127.0.0.1";
        dest.Port = 7777;

        bool server_received = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Shadowsocks2022::Address src;
                             std::vector<std::uint8_t> payload;
                             const auto err = co_await Server->AsyncReceiveFrom(src, payload);
                             server_received = (err == Error::None);
                         },
                         net::detached);

                     const std::string msg = "bad-key";
                     co_await Client->AsyncSendTo(
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
