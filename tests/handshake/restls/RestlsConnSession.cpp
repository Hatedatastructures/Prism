/**
 * @file RestlsConnSession.cpp
 * @brief Restls conn 会话层双向测试（client + server 视角）
 * @details 覆盖：
 * 1. 客户端 connect / 服务端 accept 握手（同一 server_random）→ 双向回显
 * 2. 派生密钥一致性校验（secret()）
 * 3. 错误分支：bad_length（server_random 长度非法）/ not_open（未握手读写）
 * 4. 装饰器链方法：executor / close / cancel / next_layer / release
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
#include <common/stealth/restls/restls.hpp>
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

    /// 构造 32 字节服务端随机数（固定模式）
    auto make_server_random() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> rnd{};
        for (std::size_t i = 0; i < rnd.size(); ++i)
        {
            rnd[i] = static_cast<std::uint8_t>(i * 5 + 1);
        }
        return rnd;
    }

    TEST(RestlsConnSession, HandshakeClientServerEcho)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        const auto rnd = make_server_random();
        const std::string payload = "restls echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：accept 握手 → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, conn] = co_await restls::accept(
                             std::make_shared<memory_stream>(std::move(b)),
                             restls::server_config{"pw123456"}, rnd);
                         if (err != error::none || !conn)
                         {
                             EXPECT_TRUE(false) << "accept failed";
                             co_return;
                         }
                         // 服务端派生密钥与客户端一致
                         EXPECT_EQ(conn->secret(), restls::derive_secret("pw123456"));
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

                     auto [herr, cli] = co_await restls::connect(std::make_shared<memory_stream>(std::move(a)),
                                                                 restls::client_config{"pw123456"}, rnd);
                     EXPECT_EQ(herr, error::none);
                     if (!cli)
                     {
                         co_return;
                     }
                     EXPECT_EQ(cli->secret(), restls::derive_secret("pw123456"));
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

    TEST(RestlsConnSession, BadLengthRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // server_random 长度非法（31 字节）→ bad_length
                     const std::array<std::uint8_t, 31> short_rnd{};
                     auto [herr, cli] = co_await restls::connect(
                         std::make_shared<memory_stream>(std::move(a)), restls::client_config{"pw"},
                         std::span<const std::uint8_t>(short_rnd));
                     EXPECT_EQ(herr, error::bad_length);
                     EXPECT_FALSE(cli);

                     auto c = std::make_shared<restls::conn>(std::make_shared<memory_stream>(std::move(b)),
                                                             "pw");
                     const std::array<std::uint8_t, 33> long_rnd{};
                     const auto serr = co_await c->read_handshake(std::span<const std::uint8_t>(long_rnd));
                     EXPECT_EQ(serr, error::bad_length);
                 });
    }

    TEST(RestlsConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 conn：读写返回 not_open
                     auto c = std::make_shared<restls::conn>(std::make_shared<memory_stream>(std::move(a)),
                                                             "pw");
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
                     const restls::conn *const_c = c.get();
                     EXPECT_NE(const_c->next_layer(), nullptr);
                     auto released = c->release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->next_layer(), nullptr);
                 });
    }

} // namespace
