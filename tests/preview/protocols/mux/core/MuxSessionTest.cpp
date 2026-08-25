/**
 * @file MuxSessionTest.cpp
 * @brief 多路复用会话测试（smux / yamux / h2mux 独立实现）
 * @details 覆盖：Open/Accept、双向数据传输、多流并发、FIN 关闭语义。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <common/Protocols/Mux/Smux/Smux.hpp>
#include <common/Protocols/Mux/Yamux/Yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    using namespace Preview::Mux;

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

    /// 通用会话测试：cl/sv 为 (Client, Server) 值对象，payload 回显
    template <typename Client, typename Server>
    auto run_session(net::io_context &ioc, Client &cl, Server &sv, const std::size_t payload_size)
        -> std::size_t
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        EXPECT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        EXPECT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        std::size_t received = 0;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto s = co_await sv.AcceptStream();
                         if (!s)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         std::array<std::byte, 64 * 1024> buf{};
                         while (true)
                         {
                             std::error_code ec;
                             const auto n = co_await s->AsyncReadSome(std::span<std::byte>(buf), ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             received += n;
                             ec.clear();
                             (void)co_await s->AsyncWriteSome(std::span<const std::byte>(buf.data(), n),
                                                                ec);
                         }
                         s->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto s = co_await cl.OpenStream();
                     if (!s)
                     {
                         EXPECT_TRUE(false) << "Open Failed";
                         co_return;
                     }
                     std::string payload(payload_size, 'M');
                     std::error_code ec;
                     (void)co_await s->AsyncWriteSome(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     std::string echoed;
                     std::array<std::byte, 64 * 1024> buf{};
                     while (echoed.size() < payload.size())
                     {
                         ec.clear();
                         const auto n = co_await s->AsyncReadSome(std::span<std::byte>(buf), ec);
                         if (ec || n == 0)
                         {
                             break;
                         }
                         echoed.append(reinterpret_cast<const char *>(buf.data()), n);
                     }
                     EXPECT_EQ(echoed, payload);
                     s->Close();
                     cl.Close();
                     sv.Close();
                 });
        return received;
    }

    TEST(MuxSession, SmuxEcho)
    {
        net::io_context ioc;
        Smux::Client cl;
        Smux::Server sv;
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, YamuxEcho)
    {
        net::io_context ioc;
        Yamux::Client cl;
        Yamux::Server sv;
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, H2muxEcho)
    {
        net::io_context ioc;
        H2Mux::Client cl;
        H2Mux::Server sv;
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, SmuxMultiStream)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Smux::Client cl;
        Smux::Server sv;
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        constexpr int kStreams = 8;
        constexpr std::size_t kPayload = 64 * 1024;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         std::array<std::byte, 4096> buf{};
                         for (int i = 0; i < kStreams; ++i)
                         {
                             auto s = co_await sv.AcceptStream();
                             if (!s)
                             {
                                 continue;
                             }
                             std::size_t got = 0;
                             while (got < kPayload)
                             {
                                 std::error_code ec;
                                 const auto n = co_await s->AsyncReadSome(std::span<std::byte>(buf), ec);
                                 if (ec || n == 0)
                                 {
                                     break;
                                 }
                                 got += n;
                             }
                             EXPECT_EQ(got, kPayload);
                             s->Close();
                         }
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     std::string payload(kPayload, 'C');
                     for (int i = 0; i < kStreams; ++i)
                     {
                         auto s = co_await cl.OpenStream();
                         if (!s)
                         {
                             continue;
                         }
                         std::error_code ec;
                         (void)co_await s->AsyncWriteSome(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                        payload.size()),
                             ec);
                         s->Close();
                         // 让出调度：保证对端 Accept 与帧循环有机会推进
                         co_await net::post(ioc.get_executor(), net::use_awaitable);
                     }
                     cl.Close();
                     sv.Close();
                 });
    }

    TEST(MuxSession, FactorySmux)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Smux::Client cl;
        Smux::Server sv;
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto s = co_await sv.AcceptStream();
                         if (!s)
                         {
                             co_return;
                         }
                         std::array<std::byte, 4096> buf{};
                         while (true)
                         {
                             std::error_code ec;
                             const auto n = co_await s->AsyncReadSome(std::span<std::byte>(buf), ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                         }
                         s->Close();
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);
                     auto s = co_await cl.OpenStream();
                     if (!s)
                     {
                         co_return;
                     }
                     const std::string payload = "factory smux";
                     std::error_code ec;
                     (void)co_await s->AsyncWriteSome(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     s->Close();
                     cl.Close();
                     sv.Close();
                 });
    }

} // namespace
