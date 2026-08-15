/**
 * @file ShadowtlsConnSession.cpp
 * @brief ShadowTLS v3 conn 会话层双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect / 服务端 accept 握手（ClientHello session_id HMAC）→ 双向回显
 * 2. 错误分支：bad_auth（密码不匹配）/ not_open（未握手读写）
 * 3. 装饰器链方法：executor / close / cancel / next_layer / release
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
#include <common/stealth/shadowtls/shadowtls.hpp>
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

    /// 构造 32 字节随机数（固定模式）
    auto make_random(std::uint8_t seed) -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> rnd{};
        for (std::size_t i = 0; i < rnd.size(); ++i)
        {
            rnd[i] = static_cast<std::uint8_t>(i * 3 + seed);
        }
        return rnd;
    }

    TEST(ShadowtlsConnSession, HandshakeClientServerEcho)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto server_rnd = make_random(0x11);
        const auto client_rnd = make_random(0x22);
        const std::string payload = "shadowtls echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 校验 ClientHello session_id HMAC → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, conn] =
                             co_await shadowtls::accept(std::make_shared<memory_stream>(std::move(b)),
                                                         shadowtls::server_config{"pw123456"});
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
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

                     auto [herr, cli] = co_await shadowtls::connect(
                         std::make_shared<memory_stream>(std::move(a)), shadowtls::client_config{"pw123456"},
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(herr, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
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

    TEST(ShadowtlsConnSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：密码不匹配 → session_id HMAC 校验失败 → bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, conn] =
                             co_await shadowtls::accept(std::make_shared<memory_stream>(std::move(b)),
                                                         shadowtls::server_config{"expect-pw"});
                         EXPECT_EQ(err, error::bad_auth);
                         EXPECT_FALSE(conn);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto server_rnd = make_random(0x33);
                     const auto client_rnd = make_random(0x44);
                     auto [herr, cli] = co_await shadowtls::connect(
                         std::make_shared<memory_stream>(std::move(a)), shadowtls::client_config{"wrong-pw"},
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(herr, error::none); // 客户端只发送，不感知认证结果
                     if (cli)
                     {
                         cli->close();
                     }
                 });
    }

    TEST(ShadowtlsConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 conn：读写返回 not_open
                     auto c = std::make_shared<shadowtls::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "pw");
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
                     const shadowtls::conn<> *const_c = c.get();
                     EXPECT_NE(const_c->next_layer(), nullptr);
                     auto released = c->release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->next_layer(), nullptr);
                 });
    }

} // namespace
