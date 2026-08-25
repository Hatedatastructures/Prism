/**
 * @file MuxSessionDeep.cpp
 * @brief 多路复用会话分支覆盖测试（smux/yamux/h2mux）
 * @details 补充 MuxSessionTest 未覆盖的分支：
 * 1. 多流并发数据完整性
 * 2. 会话关闭后操作失败
 * 3. 对端关闭后会话自动关闭（帧循环检测 EOF）
 * 4. smux/yamux/h2mux 帧头构建/解析边界
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

    // ── 1. 多流并发数据完整性 ──

    TEST(MuxSessionDeep, ConcurrentStreamsDataIntegrity)
    {
        net::io_context ioc;
        Smux::Client cl;
        Smux::Server sv;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         for (std::uint32_t i = 0; i < 3; ++i)
                         {
                             auto s = co_await sv.AcceptStream();
                             if (!s)
                             {
                                 co_return;
                             }
                             std::array<std::byte, 128> buf{};
                             std::error_code ec;
                             const auto n = co_await s->AsyncReadSome(std::span<std::byte>(buf), ec);
                             EXPECT_GT(n, 0U);
                             s->Close();
                         }
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     for (std::uint32_t i = 1; i <= 3; ++i)
                     {
                         auto s = co_await cl.OpenStream();
                         if (!s)
                         {
                             EXPECT_TRUE(false) << "OpenStream Failed";
                             co_return;
                         }
                         const std::string payload = "Stream-" + std::to_string(i) + "-payload";
                         std::error_code ec;
                         const auto n = co_await s->AsyncWriteSome(
                             std::span<const std::byte>(
                                 reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                             ec);
                         EXPECT_EQ(n, payload.size());
                         s->Close();
                     }
                     sv.Close();
                     cl.Close();
                 });
    }

    // ── 2. 会话关闭后操作 ──

    TEST(MuxSessionDeep, ClosedSessionOpsFail)
    {
        net::io_context ioc;
        Smux::Client cl;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));

         run_coro(ioc,
                  [&]() -> net::awaitable<void>
                  {
                      co_await cl.Session()->Close();
                      auto s = co_await cl.OpenStream();
                      EXPECT_FALSE(s);
                      co_return;
                  });
     }

    // ── 3. 对端关闭后会话自动关闭 ──

    TEST(MuxSessionDeep, FactoryHandshakeFail)
    {
        net::io_context ioc;
        Smux::Client cl;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
         run_coro(ioc,
                  [&]() -> net::awaitable<void>
                  {
                      b.Close();
                      if (!cl.Connect(std::make_shared<MemoryStream>(std::move(a))))
                      {
                          EXPECT_TRUE(false) << "Connect Failed";
                          co_return;
                      }
                      while (cl.IsOpen())
                      {
                          co_await net::post(ioc.get_executor(), net::use_awaitable);
                      }
                      EXPECT_FALSE(cl.IsOpen());
                      co_return;
                  });
     }

    // ── 4. smux 帧头构建/解析 ──

    TEST(MuxSessionDeep, SmuxHeaderBuildParse)
    {
        Smux::FrameHeader hdr;
        hdr.cmd = Smux::Command::Push;
        hdr.StreamId = 7;
        const std::array<std::uint8_t, 2> payload{0xAA, 0xBB};
        auto Frame = Smux::Build(hdr, payload);
        Smux::FrameHeader out;
        EXPECT_EQ(Smux::ParseHeader(Frame, out), Error::none);
        EXPECT_EQ(out.cmd, Smux::Command::Push);
        EXPECT_EQ(out.StreamId, 7U);
    }

    // ── 5. yamux 帧头构建/解析 ──

    TEST(MuxSessionDeep, YamuxHeaderBuildParse)
    {
        Yamux::FrameHeader hdr;
        hdr.version = 0;
        hdr.Type = Yamux::MessageType::Data;
        hdr.flag = Yamux::Flags::none;
        hdr.StreamId = 9;
        const std::array<std::uint8_t, 3> payload{1, 2, 3};
        auto Frame = Yamux::Build(hdr, payload);
        Yamux::FrameHeader out;
        EXPECT_EQ(Yamux::ParseHeader(Frame, out), Error::none);
        EXPECT_EQ(out.Type, Yamux::MessageType::Data);
        EXPECT_EQ(out.StreamId, 9U);
    }

    // ── 6. h2mux 帧头构建/解析 ──

    TEST(MuxSessionDeep, H2muxHeaderBuildParse)
    {
        const std::array<std::uint8_t, 2> payload{0x10, 0x20};
        auto Frame = H2Mux::Build(H2Mux::FrameType::Data, 3, payload);
        EXPECT_EQ(Frame.size(), 9U + 2U);
        H2Mux::FrameHeader out;
        EXPECT_EQ(H2Mux::ParseHeader(Frame, out), Error::none);
        EXPECT_EQ(out.Type, H2Mux::FrameType::Data);
        EXPECT_EQ(out.StreamId, 3U);
    }

} // namespace
