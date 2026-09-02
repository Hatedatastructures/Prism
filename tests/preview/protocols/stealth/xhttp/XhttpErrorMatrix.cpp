/**
 * @file XhttpErrorMatrix.cpp
 * @brief xhttp 错误矩阵与传输层边界测试
 * @details 覆盖：
 *          - Config 边界（空 Path 禁用 / 非空启用）
 *          - XhttpTransport：EOF / 关闭 / 写缓冲后 flush / 数据往返
 *          - 读超时与取消路径
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Protocols/Xhttp/Conn.hpp>
#include <preview/Protocols/Xhttp/Types.hpp>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;

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

    struct WriteProbe
    {
        int Active{0};
        int MaxActive{0};
        int Completed{0};
        bool Failed{false};
        std::string Order;
    };

    auto ProbeWrite(net::any_io_executor Ex, const std::shared_ptr<WriteProbe> &Probe,
                    std::span<const std::byte> Data) -> net::awaitable<void>
    {
        ++Probe->Active;
        Probe->MaxActive = (std::max)(Probe->MaxActive, Probe->Active);
        co_await net::post(Ex, net::use_awaitable);
        Probe->Order.append(reinterpret_cast<const char *>(Data.data()), Data.size());
        --Probe->Active;
        co_return;
    }

    auto MakeTransportProbe(net::any_io_executor Ex, const std::shared_ptr<WriteProbe> &Probe)
        -> Xhttp::XhttpTransport::WriteCb
    {
        return [Ex, Probe](std::int32_t, std::span<const std::byte> Data)
        {
            return ProbeWrite(Ex, Probe, Data);
        };
    }

    auto MakeWireProbe(net::any_io_executor Ex, const std::shared_ptr<WriteProbe> &Probe)
        -> Xhttp::WireWriter::Sink
    {
        return [Ex, Probe](std::span<const std::byte> Data)
        {
            return ProbeWrite(Ex, Probe, Data);
        };
    }

    auto TransportWriteTask(const std::shared_ptr<Xhttp::XhttpTransport> &Transport,
                            const std::shared_ptr<WriteProbe> &Probe,
                            std::vector<std::byte> Data) -> net::awaitable<void>
    {
        std::error_code ec;
        const auto N = co_await Transport->async_write_some(Data, ec);
        if (ec || N != Data.size())
        {
            Probe->Failed = true;
        }
        ++Probe->Completed;
        co_return;
    }

    auto WireWriteTask(const std::shared_ptr<Xhttp::WireWriter> &Writer,
                       const std::shared_ptr<WriteProbe> &Probe,
                       std::vector<std::byte> Data) -> net::awaitable<void>
    {
        try
        {
            co_await Writer->Write(Data);
        }
        catch (...)
        {
            Probe->Failed = true;
        }
        ++Probe->Completed;
        co_return;
    }

    auto RunConcurrentTransportWrites(const std::shared_ptr<Xhttp::XhttpTransport> &Transport,
                                      const std::shared_ptr<WriteProbe> &Probe)
        -> net::awaitable<void>
    {
        const auto Ex = Transport->Executor();
        auto First = net::co_spawn(
            Ex, TransportWriteTask(Transport, Probe, {std::byte{'A'}}), net::use_awaitable);
        auto Second = net::co_spawn(
            Ex, TransportWriteTask(Transport, Probe, {std::byte{'B'}}), net::use_awaitable);
        using net::experimental::awaitable_operators::operator&&;
        co_await (std::move(First) && std::move(Second));
    }

    auto RunConcurrentWireWrites(net::any_io_executor Ex,
                                 const std::shared_ptr<Xhttp::WireWriter> &Writer,
                                 const std::shared_ptr<WriteProbe> &Probe)
        -> net::awaitable<void>
    {
        auto First = net::co_spawn(
            Ex, WireWriteTask(Writer, Probe, {std::byte{'A'}}), net::use_awaitable);
        auto Second = net::co_spawn(
            Ex, WireWriteTask(Writer, Probe, {std::byte{'B'}}), net::use_awaitable);
        using net::experimental::awaitable_operators::operator&&;
        co_await (std::move(First) && std::move(Second));
    }

    TEST(XhttpErrorMatrix, ConfigEnabledBoundary)
    {
        Xhttp::Config cfg;
        EXPECT_TRUE(cfg.Enabled()); // 默认 "/" 启用

        Xhttp::Config Empty;
        Empty.Path = "";
        EXPECT_FALSE(Empty.Enabled());

        Xhttp::Config custom;
        custom.Path = "/custom";
        EXPECT_TRUE(custom.Enabled());
    }

    TEST(XhttpErrorMatrix, TransportEofAndClose)
    {
        net::io_context ioc;
        auto t = std::make_shared<Xhttp::XhttpTransport>(
            ioc.get_executor(),
            [](std::int32_t, std::span<const std::byte>) -> net::awaitable<void>
            { co_return; });

        std::error_code ec;
        std::size_t n = 0;
        std::array<std::byte, 16> buf{};

        // 关闭 → not_connected
        t->Close();
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     n = co_await t->async_read_some(std::span<std::byte>(buf), ec);
                 });
        EXPECT_NE(ec, std::error_code{});

        // EOF 通知 → 0 + eof（重新打开后）
        auto t2 = std::make_shared<Xhttp::XhttpTransport>(
            ioc.get_executor(),
            [](std::int32_t, std::span<const std::byte>) -> net::awaitable<void>
            { co_return; });
        t2->NotifyEof();
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
        auto t = std::make_shared<Xhttp::XhttpTransport>(
            ioc.get_executor(),
            [&](std::int32_t sid, std::span<const std::byte> Data) -> net::awaitable<void>
            {
                co_await net::post(ioc.get_executor(), net::use_awaitable);
                flushed_stream = sid;
                flushed_data.assign(reinterpret_cast<const char *>(Data.data()), Data.size());
                co_return;
            });

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 未绑定流（-1）写 → 缓冲
                     std::error_code ec;
                     const std::string msg = "buffered";
                     co_await t->async_write_some(
                         AsBytesSpan(std::string_view(msg)), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(flushed_stream, -99); // 未 flush

                     // 绑定流 → flush
                     t->BindStream(7);
                     net::steady_timer Wait(ioc);
                     Wait.expires_after(std::chrono::milliseconds(50));
                     co_await Wait.async_wait(net::use_awaitable);
                 });
        EXPECT_EQ(flushed_stream, 7);
        EXPECT_EQ(flushed_data, "buffered");
    }

    TEST(XhttpErrorMatrix, TransportSerializesConcurrentWrites)
    {
        net::io_context ioc;
        auto Probe = std::make_shared<WriteProbe>();
        auto t = std::make_shared<Xhttp::XhttpTransport>(
            ioc.get_executor(),
            MakeTransportProbe(ioc.get_executor(), Probe));
        t->BindStream(7);

        std::exception_ptr ep;
        net::co_spawn(ioc, RunConcurrentTransportWrites(t, Probe),
                      [&](std::exception_ptr Error) { ep = Error; });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
        EXPECT_FALSE(Probe->Failed);
        EXPECT_EQ(Probe->Completed, 2);
        EXPECT_EQ(Probe->MaxActive, 1);
        EXPECT_EQ(Probe->Order, "AB");
    }

    TEST(XhttpErrorMatrix, WireWriterSerializesPhysicalWrites)
    {
        net::io_context ioc;
        auto Probe = std::make_shared<WriteProbe>();
        auto writer = std::make_shared<Xhttp::WireWriter>(
            ioc.get_executor(), MakeWireProbe(ioc.get_executor(), Probe));

        std::exception_ptr ep;
        net::co_spawn(ioc, RunConcurrentWireWrites(ioc.get_executor(), writer, Probe),
                      [&](std::exception_ptr Error) { ep = Error; });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
        EXPECT_FALSE(Probe->Failed);
        EXPECT_EQ(Probe->Completed, 2);
        EXPECT_EQ(Probe->MaxActive, 1);
        EXPECT_EQ(Probe->Order, "AB");
    }

    TEST(XhttpErrorMatrix, TransportChannelBackpressureCloses)
    {
        net::io_context ioc;
        auto t = std::make_shared<Xhttp::XhttpTransport>(
            ioc.get_executor(),
            [](std::int32_t, std::span<const std::byte>) -> net::awaitable<void>
            { co_return; });
        const std::array<std::byte, 1> payload{std::byte{0x01}};

        for (std::size_t index = 0; index < 65; ++index)
        {
            t->Push(payload);
        }

        std::array<std::byte, 1> Buffer{};
        std::error_code ec;
        std::size_t n = 0;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     n = co_await t->async_read_some(Buffer, ec);
                 });

        EXPECT_EQ(n, 0U);
        EXPECT_NE(ec, std::error_code{});
    }

    TEST(XhttpErrorMatrix, TransportDataRoundtrip)
    {
        net::io_context ioc;
        auto t = std::make_shared<Xhttp::XhttpTransport>(
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
                     const std::string payload = "xhttp-Data";
                     t->Push(AsBytesSpan(std::string_view(payload)));
                     net::steady_timer Wait(ioc);
                     Wait.expires_after(std::chrono::milliseconds(50));
                     co_await Wait.async_wait(net::use_awaitable);
                 });
        EXPECT_EQ(got, "xhttp-Data");
    }

} // namespace
