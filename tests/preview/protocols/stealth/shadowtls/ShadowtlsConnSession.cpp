/**
 * @file ShadowtlsConnSession.cpp
 * @brief ShadowTLS v3 Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（ClientHello SessionId HMAC）→ 双向回显
 * 2. 错误分支：bad_auth（密码不匹配）/ not_open（未握手读写）
 * 3. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Shadowtls/Shadowtls.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
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
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x11);
        const auto client_rnd = make_random(0x22);
        const std::string payload = "shadowtls echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 校验 ClientHello SessionId HMAC → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, Conn] =
                             co_await Shadowtls::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                         Shadowtls::ServerConfig{"pw123456"});
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await Conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto [herr, cli] = co_await Shadowtls::Connect({
                         std::make_shared<MemoryStream>(std::move(a)), Shadowtls::ClientConfig{"pw123456"},
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd)});
                     EXPECT_EQ(herr, Error::None);
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
                     cli->Close();
                 });
    }

    TEST(ShadowtlsConnSession, BadAuthRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：密码不匹配 → SessionId HMAC 校验失败 → bad_auth
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, Conn] =
                             co_await Shadowtls::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                         Shadowtls::ServerConfig{"Expect-pw"});
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     const auto server_rnd = make_random(0x33);
                     const auto client_rnd = make_random(0x44);
                     auto [herr, cli] = co_await Shadowtls::Connect({
                         std::make_shared<MemoryStream>(std::move(a)), Shadowtls::ClientConfig{"wrong-pw"},
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd)});
                     EXPECT_EQ(herr, Error::None); // 客户端只发送，不感知认证结果
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(ShadowtlsConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 Conn：读写返回 not_open
                     auto c = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     c->Close();
                     c->Cancel();
                     EXPECT_TRUE(c->Executor());
                     EXPECT_NE(c->NextLayer(), nullptr);
                     EXPECT_NE(c->lowest_layer<MemoryStream>(), nullptr);
                     const Shadowtls::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
                     auto released = c->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr);
                 });
    }

} // namespace
