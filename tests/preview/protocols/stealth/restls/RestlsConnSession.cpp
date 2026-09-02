/**
 * @file RestlsConnSession.cpp
 * @brief Restls Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（同一 ServerRandom）→ 双向回显
 * 2. 派生密钥一致性校验（Secret()）
 * 3. 错误分支：bad_length（ServerRandom 长度非法）/ not_open（未握手读写）
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
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
#include <preview/Protocols/Restls/Restls.hpp>
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
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto rnd = make_server_random();
        const std::string payload = "restls echo payload";

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 回显
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto [err, Conn] = co_await Restls::Accept(
                             std::make_shared<MemoryStream>(std::move(b)),
                             Restls::ServerConfig{"pw123456"}, rnd);
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         // 服务端派生密钥与客户端一致
                         EXPECT_EQ(Conn->Secret(), Restls::DeriveSecret("pw123456"));
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

                     auto [herr, cli] = co_await Restls::Connect(std::make_shared<MemoryStream>(std::move(a)),
                                                                 Restls::ClientConfig{"pw123456"}, rnd);
                     EXPECT_EQ(herr, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     EXPECT_EQ(cli->Secret(), Restls::DeriveSecret("pw123456"));
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

    TEST(RestlsConnSession, BadLengthRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // ServerRandom 长度非法（31 字节）→ bad_length
                     const std::array<std::uint8_t, 31> short_rnd{};
                     auto [herr, cli] = co_await Restls::Connect(
                         std::make_shared<MemoryStream>(std::move(a)), Restls::ClientConfig{"pw"},
                         std::span<const std::uint8_t>(short_rnd));
                     EXPECT_EQ(herr, Error::BadLength);
                     EXPECT_FALSE(cli);

                     auto c = std::make_shared<Restls::Conn<>>(std::make_shared<MemoryStream>(std::move(b)),
                                                              "pw");
                     const std::array<std::uint8_t, 33> long_rnd{};
                     const auto serr = co_await c->ReadHandshake(std::span<const std::uint8_t>(long_rnd));
                     EXPECT_EQ(serr, Error::BadLength);
                 });
    }

    TEST(RestlsConnSession, NotOpenRejected)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未握手 Conn：读写返回 not_open
                     auto c = std::make_shared<Restls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                              "pw");
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
                     const Restls::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
                     auto released = c->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr);
                 });
    }

} // namespace
