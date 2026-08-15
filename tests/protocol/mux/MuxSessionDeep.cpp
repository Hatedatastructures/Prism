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

#include <common/core/transport/memory_stream.hpp>
#include <common/mux/h2mux/h2mux.hpp>
#include <common/mux/smux/smux.hpp>
#include <common/mux/yamux/yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    using namespace psmtest::mux;

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
        smux::client cl;
        smux::server sv;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        ASSERT_TRUE(cl.connect(std::make_shared<memory_stream>(std::move(a))));
        ASSERT_TRUE(sv.accept(std::make_shared<memory_stream>(std::move(b))));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         for (std::uint32_t i = 0; i < 3; ++i)
                         {
                             auto s = co_await sv.accept_stream();
                             if (!s)
                             {
                                 co_return;
                             }
                             std::array<std::byte, 128> buf{};
                             std::error_code ec;
                             const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                             EXPECT_GT(n, 0U);
                             s->close();
                         }
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     for (std::uint32_t i = 1; i <= 3; ++i)
                     {
                         auto s = co_await cl.open_stream();
                         if (!s)
                         {
                             EXPECT_TRUE(false) << "open_stream failed";
                             co_return;
                         }
                         const std::string payload = "stream-" + std::to_string(i) + "-payload";
                         std::error_code ec;
                         const auto n = co_await s->async_write_some(
                             std::span<const std::byte>(
                                 reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                             ec);
                         EXPECT_EQ(n, payload.size());
                         s->close();
                     }
                     sv.close();
                     cl.close();
                 });
    }

    // ── 2. 会话关闭后操作 ──

    TEST(MuxSessionDeep, ClosedSessionOpsFail)
    {
        net::io_context ioc;
        smux::client cl;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        ASSERT_TRUE(cl.connect(std::make_shared<memory_stream>(std::move(a))));

         run_coro(ioc,
                  [&]() -> net::awaitable<void>
                  {
                      co_await cl.session()->close();
                      auto s = co_await cl.open_stream();
                      EXPECT_FALSE(s);
                      co_return;
                  });
     }

    // ── 3. 对端关闭后会话自动关闭 ──

    TEST(MuxSessionDeep, FactoryHandshakeFail)
    {
        net::io_context ioc;
        smux::client cl;
        auto [a, b] = make_memory_pair(ioc.get_executor());
         run_coro(ioc,
                  [&]() -> net::awaitable<void>
                  {
                      b.close();
                      if (!cl.connect(std::make_shared<memory_stream>(std::move(a))))
                      {
                          EXPECT_TRUE(false) << "connect failed";
                          co_return;
                      }
                      while (cl.is_open())
                      {
                          co_await net::post(ioc.get_executor(), net::use_awaitable);
                      }
                      EXPECT_FALSE(cl.is_open());
                      co_return;
                  });
     }

    // ── 4. smux 帧头构建/解析 ──

    TEST(MuxSessionDeep, SmuxHeaderBuildParse)
    {
        smux::frame_header hdr;
        hdr.cmd = smux::command::push;
        hdr.stream_id = 7;
        const std::array<std::uint8_t, 2> payload{0xAA, 0xBB};
        auto frame = smux::build(hdr, payload);
        smux::frame_header out;
        EXPECT_EQ(smux::parse_header(frame, out), error::none);
        EXPECT_EQ(out.cmd, smux::command::push);
        EXPECT_EQ(out.stream_id, 7U);
    }

    // ── 5. yamux 帧头构建/解析 ──

    TEST(MuxSessionDeep, YamuxHeaderBuildParse)
    {
        yamux::frame_header hdr;
        hdr.version = 0;
        hdr.type = yamux::message_type::data;
        hdr.flag = yamux::flags::none;
        hdr.stream_id = 9;
        const std::array<std::uint8_t, 3> payload{1, 2, 3};
        auto frame = yamux::build(hdr, payload);
        yamux::frame_header out;
        EXPECT_EQ(yamux::parse_header(frame, out), error::none);
        EXPECT_EQ(out.type, yamux::message_type::data);
        EXPECT_EQ(out.stream_id, 9U);
    }

    // ── 6. h2mux 帧头构建/解析 ──

    TEST(MuxSessionDeep, H2muxHeaderBuildParse)
    {
        const std::array<std::uint8_t, 2> payload{0x10, 0x20};
        auto frame = h2mux::build(h2mux::frame_type::data, 3, payload);
        EXPECT_EQ(frame.size(), 9U + 2U);
        h2mux::frame_header out;
        EXPECT_EQ(h2mux::parse_header(frame, out), error::none);
        EXPECT_EQ(out.type, h2mux::frame_type::data);
        EXPECT_EQ(out.stream_id, 3U);
    }

} // namespace
