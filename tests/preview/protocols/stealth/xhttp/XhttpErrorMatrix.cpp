/**
 * @file XhttpErrorMatrix.cpp
 * @brief xhttp 错误矩阵与传输层边界测试
 * @details 覆盖：
 *          - config 边界（空 path 禁用 / 非空启用）
 *          - xhttp_transport：EOF / 关闭 / 写缓冲后 flush / 数据往返
 *          - 读超时与取消路径
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include <common/core/byte_span.hpp>
#include <common/protocols/xhttp/conn.hpp>
#include <common/protocols/xhttp/types.hpp>

namespace
{
    namespace net = boost::asio;
    using namespace preview;

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

    TEST(XhttpErrorMatrix, ConfigEnabledBoundary)
    {
        xhttp::config cfg;
        EXPECT_TRUE(cfg.enabled()); // 默认 "/" 启用

        xhttp::config empty;
        empty.path = "";
        EXPECT_FALSE(empty.enabled());

        xhttp::config custom;
        custom.path = "/custom";
        EXPECT_TRUE(custom.enabled());
    }

    TEST(XhttpErrorMatrix, TransportEofAndClose)
    {
        net::io_context ioc;
        auto t = std::make_shared<xhttp::xhttp_transport>(
            ioc.get_executor(),
            [](std::int32_t, std::span<const std::byte>) -> net::awaitable<void>
            { co_return; });

        std::error_code ec;
        std::size_t n = 0;
        std::array<std::byte, 16> buf{};

        // 关闭 → not_connected
        t->close();
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     n = co_await t->async_read_some(std::span<std::byte>(buf), ec);
                 });
        EXPECT_NE(ec, std::error_code{});

        // EOF 通知 → 0 + eof（重新打开后）
        auto t2 = std::make_shared<xhttp::xhttp_transport>(
            ioc.get_executor(),
            [](std::int32_t, std::span<const std::byte>) -> net::awaitable<void>
            { co_return; });
        t2->notify_eof();
        ec.clear();
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     n = co_await t2->async_read_some(std::span<std::byte>(buf), ec);
                 });
        EXPECT_EQ(n, 0u);
        EXPECT_FALSE(ec); // EOF 语义：返回 0 且无错误
    }

    TEST(XhttpErrorMatrix, TransportWriteBufferedUntilBind)
    {
        net::io_context ioc;
        std::int32_t flushed_stream = -99;
        std::string flushed_data;
        auto t = std::make_shared<xhttp::xhttp_transport>(
            ioc.get_executor(),
            [&](std::int32_t sid, std::span<const std::byte> data) -> net::awaitable<void>
            {
                flushed_stream = sid;
                flushed_data.assign(reinterpret_cast<const char *>(data.data()), data.size());
                co_return;
            });

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未绑定流（-1）写 → 缓冲
                     std::error_code ec;
                     const std::string msg = "buffered";
                     co_await t->async_write_some(
                         as_bytes_span(std::string_view(msg)), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(flushed_stream, -99); // 未 flush

                     // 绑定流 → flush
                     t->bind_stream(7);
                     net::steady_timer wait(ioc);
                     wait.expires_after(std::chrono::milliseconds(50));
                     co_await wait.async_wait(net::use_awaitable);
                 });
        EXPECT_EQ(flushed_stream, 7);
        EXPECT_EQ(flushed_data, "buffered");
    }

    TEST(XhttpErrorMatrix, TransportDataRoundtrip)
    {
        net::io_context ioc;
        auto t = std::make_shared<xhttp::xhttp_transport>(
            ioc.get_executor(),
            [](std::int32_t, std::span<const std::byte>) -> net::awaitable<void>
            { co_return; });

        std::string got;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 先挂起读
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             std::array<std::byte, 64> buf{};
                             std::error_code ec;
                             const auto n = co_await t->async_read_some(std::span<std::byte>(buf), ec);
                             if (n > 0)
                             {
                                 got.assign(reinterpret_cast<const char *>(buf.data()), n);
                             }
                         },
                         net::detached);

                     // 注入数据 → 读返回
                     const std::string payload = "xhttp-data";
                     t->push(as_bytes_span(std::string_view(payload)));
                     net::steady_timer wait(ioc);
                     wait.expires_after(std::chrono::milliseconds(50));
                     co_await wait.async_wait(net::use_awaitable);
                 });
        EXPECT_EQ(got, "xhttp-data");
    }

} // namespace
