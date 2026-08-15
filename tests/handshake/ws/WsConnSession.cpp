/**
 * @file WsConnSession.cpp
 * @brief WebSocket conn 会话层双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect / 服务端 accept Upgrade 握手（Sec-WebSocket-Key/Accept）→ 双向回显
 * 2. 错误分支：bad_magic（非 Upgrade 请求 / 非 101 响应）/ bad_auth（Accept 不匹配）
 * 3. 装饰器链方法：executor / close / cancel / next_layer / release / accept()
 * @note 使用 make_memory_pair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/core/transport/memory_stream.hpp>
#include <common/stealth/ws/ws.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 标准测试密钥（RFC 6455 示例）
    inline constexpr const char *kTestKey = "dGhlIHNhbXBsZSBub25jZQ==";

    TEST(WsConnSession, HandshakeClientServerEcho)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const std::string payload = "ws echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 解析 Upgrade 请求 → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, key, conn] =
                             co_await ws::accept(std::make_shared<memory_stream>(std::move(b)),
                                                 ws::server_config{});
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         EXPECT_EQ(key, kTestKey);
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                         EXPECT_FALSE(ec);
                         conn->close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     ws::client_config cfg;
                     cfg.host = "example.com";
                     cfg.key = kTestKey;
                     auto [herr, cli] = co_await ws::connect(std::make_shared<memory_stream>(std::move(a)), cfg);
                     EXPECT_EQ(herr, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
                     // accept() 返回服务端计算的 Sec-WebSocket-Accept
                     EXPECT_EQ(cli->accept(), ws::compute_accept(kTestKey));
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 1024> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                     cli->close();
                 });
    }

    TEST(WsConnSession, ServerRejectsNonUpgrade)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：普通 HTTP 请求（无 Upgrade）→ bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, key, conn] =
                             co_await ws::accept(std::make_shared<memory_stream>(std::move(b)),
                                                 ws::server_config{});
                         EXPECT_EQ(err, error::bad_magic);
                         EXPECT_FALSE(conn);
                         (void)key;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::string plain = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
                     std::error_code ec;
                     co_await a.async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(plain.data()),
                                                    plain.size()),
                         ec);
                     a.close();
                 });
    }

    TEST(WsConnSession, ServerRejectsMissingKey)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：有 Upgrade 但无 Sec-WebSocket-Key → bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, key, conn] =
                             co_await ws::accept(std::make_shared<memory_stream>(std::move(b)),
                                                 ws::server_config{});
                         EXPECT_EQ(err, error::bad_magic);
                         EXPECT_FALSE(conn);
                         (void)key;
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                             "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
                     std::error_code ec;
                     co_await a.async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(req.data()),
                                                    req.size()),
                         ec);
                     a.close();
                 });
    }

    TEST(WsConnSession, ClientRejectsNon101)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：回复 200（非 101）→ 客户端 bad_magic
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n = co_await b.async_read_some(as_bytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     ws::client_config cfg;
                     cfg.host = "example.com";
                     cfg.key = kTestKey;
                     auto [herr, cli] = co_await ws::connect(std::make_shared<memory_stream>(std::move(a)), cfg);
                     EXPECT_EQ(herr, error::bad_magic);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(WsConnSession, ClientRejectsBadAccept)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 原始服务端：101 但 Sec-WebSocket-Accept 错误 → 客户端 bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 512> req{};
                         std::error_code ec;
                         const auto n = co_await b.async_read_some(as_bytes(std::span<std::uint8_t>(req)), ec);
                         EXPECT_GT(n, 0u);
                         const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                                                  "Upgrade: websocket\r\n"
                                                  "Connection: Upgrade\r\n"
                                                  "Sec-WebSocket-Accept: wrong-accept-value\r\n\r\n";
                         co_await b.async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(resp.data()),
                                                        resp.size()),
                             ec);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     ws::client_config cfg;
                     cfg.host = "example.com";
                     cfg.key = kTestKey;
                     auto [herr, cli] = co_await ws::connect(std::make_shared<memory_stream>(std::move(a)), cfg);
                     EXPECT_EQ(herr, error::bad_auth);
                     EXPECT_FALSE(cli);
                 });
    }

    TEST(WsConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 conn：读写返回 not_open
                     auto c = std::make_shared<ws::conn<>>(std::make_shared<memory_stream>(std::move(a)));
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec.value(), static_cast<int>(error::not_open));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(error::not_open));
                     c->close();
                     c->cancel();
                     EXPECT_TRUE(c->executor());
                     EXPECT_NE(c->next_layer(), nullptr);
                     EXPECT_NE(c->lowest_layer<memory_stream>(), nullptr);
                     const ws::conn<> *const_c = c.get();
                     EXPECT_NE(const_c->next_layer(), nullptr);
                     auto released = c->release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->next_layer(), nullptr);
                     EXPECT_TRUE(c->accept().empty()); // 未握手 accept 为空
                 });
    }

} // namespace
