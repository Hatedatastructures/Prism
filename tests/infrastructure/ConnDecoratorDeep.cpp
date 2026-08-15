/**
 * @file ConnDecoratorDeep.cpp
 * @brief 测试库 conn 装饰器剩余方法深度测试
 * @details 覆盖 gun / reality / anytls / tuic 四个 conn 装饰器的
 *          executor / cancel / next_layer（const + 非 const）/ release
 *          / close 等透传方法，以及 mux::stream_transmission 的
 *          空句柄 executor 与 cancel 分支。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/core/transport/memory_stream.hpp>
#include <common/mux/smux/smux.hpp>
#include <common/mux/stream.hpp>
#include <common/proxy/tuic/conn.hpp>
#include <common/stealth/anytls/conn.hpp>
#include <common/stealth/gun/conn.hpp>
#include <common/stealth/reality/conn.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

    /**
     * @brief 驱动协程运行
     */
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

    /**
     * @brief 断言装饰器透传方法（executor/cancel/next_layer/release/close）
     */
    template <typename Conn>
    auto check_decorator(const std::shared_ptr<Conn> &conn, net::io_context &ioc) -> void
    {
        (void)conn->executor();
        EXPECT_NE(conn->next_layer(), nullptr);
        const auto *cconn = conn.get();
        EXPECT_NE(cconn->next_layer(), nullptr);
        EXPECT_EQ(conn->template lowest_layer<memory_stream>(), conn->next_layer());
        conn->cancel();
        conn->close();
        auto released = conn->release();
        EXPECT_NE(released, nullptr);
        EXPECT_EQ(conn->next_layer(), nullptr);
    }

    TEST(ConnDecorator, GunConn)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto conn = std::make_shared<gun::conn>(std::make_shared<memory_stream>(std::move(a)));

        // 未握手读写 → not_open
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await conn->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(ec);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                     ec.clear();
                     const auto w = co_await conn->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                 });

        // 客户端握手 → 数据面透传
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     EXPECT_EQ(co_await conn->write_handshake("example.com"), error::none);
                     std::array<std::byte, 8> wbuf{std::byte{0x42}};
                     std::error_code ec;
                     EXPECT_EQ(co_await conn->async_write_some(std::span<const std::byte>(wbuf), ec), 8u);
                     std::array<std::byte, 8> rbuf{};
                     EXPECT_EQ(co_await peer->async_read_some(std::span<std::byte>(rbuf), ec), 8u);
                     EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x42);
                 });

        check_decorator(conn, ioc);
    }

    TEST(ConnDecorator, RealityConn)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<reality::conn>(
            std::make_shared<memory_stream>(std::move(a)), std::array<std::uint8_t, 32>{});
        check_decorator(conn, ioc);
    }

    TEST(ConnDecorator, AnyTlsConn)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn =
            std::make_shared<anytls::conn>(std::make_shared<memory_stream>(std::move(a)), "secret");
        check_decorator(conn, ioc);
    }

    TEST(ConnDecorator, TuicConn)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto conn = std::make_shared<tuic::conn<>>(std::make_shared<memory_stream>(std::move(a)),
                                                 std::array<std::uint8_t, 16>{});
        check_decorator(conn, ioc);
    }

    TEST(ConnDecorator, StreamTransmission)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        // 空句柄：executor 返回默认执行器，cancel 空操作
        auto empty = std::make_shared<mux::stream_transmission>(nullptr);
        (void)empty->executor();
        empty->cancel();
        EXPECT_FALSE(empty->is_open());
        EXPECT_EQ(empty->handle(), nullptr);
        empty->close();
        empty->reset();
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await empty->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                     ec.clear();
                     const auto w = co_await empty->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(error::not_open));
                 });

        // 非空句柄：cancel 生效
        auto client = mux::smux::connect(std::make_shared<memory_stream>(std::move(a)));
        auto session = client.session();
        EXPECT_TRUE(client.is_open());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto handle = co_await session->open_stream();
                     if (!handle)
                     {
                         EXPECT_TRUE(false) << "open_stream failed";
                         co_return;
                     }
                     auto stream = std::make_shared<mux::stream_transmission>(handle);
                     EXPECT_TRUE(stream->is_open());
                     EXPECT_EQ(stream->handle(), handle);
                     stream->cancel();
                     std::array<std::byte, 4> buf{};
                     std::error_code ec;
                     const auto r = co_await stream->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     // 非空句柄 close / reset（co_spawn 投递）
                     stream->close();
                     stream->reset();
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_FALSE(stream->is_open());
                 });
    }

} // namespace
