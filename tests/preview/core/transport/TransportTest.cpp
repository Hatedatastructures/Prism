/**
 * @file TransportTest.cpp
 * @brief 传输抽象测试（MemoryStream / Reliable / bench）
 * @details 验证：
 *          - MemoryStream 双向数据一致与关闭语义
 *          - BenchThroughput / bench_latency 统计正确
 *          - Stream concept 约束生效
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <common/Bench/Bench.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transport/Reliable.hpp>
#include <common/Core/Transport/Stream.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    /// 回环跑一个协程并返回异常（MuxLifecycle 模式）
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

    TEST(Transport, MemoryPairEcho)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const std::string msg = "hello memory pipe";
                     EXPECT_FALSE(co_await a.WriteAll(std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size())));
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, msg.size());
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), msg);
                 });
    }

    TEST(Transport, MemoryPairCloseSemantics)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     a.Close();
                     // 对端读返回 0
                     std::array<std::uint8_t, 8> buf{};
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, 0u);
                     // 对端写返回 broken_pipe
                     const auto ec = co_await b.WriteAll(buf);
                     EXPECT_EQ(ec, net::error::broken_pipe);
                 });
    }

    TEST(Transport, BenchThroughputMemory)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        BenchReport r{};
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     BenchOptions opt;
                     opt.Total = 16 * 1024 * 1024; // 16MB
                     opt.block = 64 * 1024;
                     r = co_await BenchThroughput(a, b, opt);
                 });
        EXPECT_EQ(r.Bytes, 16u * 1024u * 1024u);
        EXPECT_GT(r.mbps, 0.0);
    }

    TEST(Transport, ReadTimeout)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        bool timed_out = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::array<std::uint8_t, 16> buf{};
                     a.SetTimeout(std::chrono::milliseconds(50));
                     const auto t0 = std::chrono::steady_clock::now();
                     const auto n = co_await a.ReadSome(buf);
                     const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - t0)
                                         .count();
                     EXPECT_EQ(n, 0u);
                     EXPECT_GE(ms, 40);
                     timed_out = true;
                 });
        EXPECT_TRUE(timed_out);
    }

    TEST(Transport, ShutdownSemantics)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     a.Shutdown();
                     // 对端读返回 0（半关）
                     std::array<std::uint8_t, 8> buf{};
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, 0u);
                     // 半关后本端仍可读对端数据
                     const auto wec = co_await b.WriteAll(buf);
                     EXPECT_FALSE(wec);
                     std::array<std::uint8_t, 8> buf2{};
                     const auto n2 = co_await a.ReadSome(buf2);
                     EXPECT_EQ(n2, 8u);
                 });
    }

    TEST(Transport, CancelSemantics)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto reader = [&]() -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 8> buf{};
                         const auto n = co_await a.ReadSome(buf);
                         EXPECT_EQ(n, 0u);
                     };
                     net::co_spawn(a.Executor(), reader(), net::detached);
                     // 让 reader 先挂起
                     co_await net::post(a.Executor(), net::use_awaitable);
                     co_await net::post(a.Executor(), net::use_awaitable);
                     a.Cancel();
                 });
    }

    TEST(Transport, MemoryStreamCloseWhileReadPending)
    {
        net::io_context ioc;
        auto [a_value, b] = MakeMemoryPair(ioc.get_executor());
        auto a = std::make_shared<MemoryStream>(std::move(a_value));
        auto read_done = std::make_shared<bool>(false);
        auto child_ep = std::make_shared<std::exception_ptr>();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto AsyncRead = [a, read_done]()
                         -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 8> Buffer{};
                         const auto n = co_await a->ReadSome(Buffer);
                         EXPECT_EQ(n, 0U);
                         *read_done = true;
                     };
                     auto on_error = [read_done, child_ep](const std::exception_ptr &ep)
                     {
                         *child_ep = ep;
                         *read_done = true;
                     };
                     net::co_spawn(a->Executor(), std::move(AsyncRead), std::move(on_error));
                     co_await net::post(a->Executor(), net::use_awaitable);
                     a->Close();

                     net::steady_timer Wait(a->Executor());
                     Wait.expires_after(std::chrono::milliseconds(20));
                     co_await Wait.async_wait(net::use_awaitable);
                 });

        ASSERT_FALSE(*child_ep);
        EXPECT_TRUE(*read_done);
    }

    TEST(Transport, MemoryStreamCancelWhileReadPending)
    {
        net::io_context ioc;
        auto [a_value, b] = MakeMemoryPair(ioc.get_executor());
        auto a = std::make_shared<MemoryStream>(std::move(a_value));
        auto read_done = std::make_shared<bool>(false);
        auto child_ep = std::make_shared<std::exception_ptr>();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto AsyncRead = [a, read_done]()
                         -> net::awaitable<void>
                     {
                         std::array<std::uint8_t, 8> Buffer{};
                         const auto n = co_await a->ReadSome(Buffer);
                         EXPECT_EQ(n, 0U);
                         *read_done = true;
                     };
                     auto on_error = [read_done, child_ep](const std::exception_ptr &ep)
                     {
                         *child_ep = ep;
                         *read_done = true;
                     };
                     net::co_spawn(a->Executor(), std::move(AsyncRead), std::move(on_error));
                     co_await net::post(a->Executor(), net::use_awaitable);
                     a->Cancel();

                     net::steady_timer Wait(a->Executor());
                     Wait.expires_after(std::chrono::milliseconds(20));
                     co_await Wait.async_wait(net::use_awaitable);
                 });

        ASSERT_FALSE(*child_ep);
        EXPECT_TRUE(*read_done);
    }

    TEST(Transport, MemoryStreamTimeoutWhileReadPending)
    {
        net::io_context ioc;
        auto [a_value, b] = MakeMemoryPair(ioc.get_executor());
        auto a = std::make_shared<MemoryStream>(std::move(a_value));
        auto read_done = std::make_shared<bool>(false);
        auto child_ep = std::make_shared<std::exception_ptr>();

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     a->SetTimeout(std::chrono::milliseconds(20));
                     auto AsyncRead = [a, read_done]()
                         -> net::awaitable<void>
                     {
                         std::array<std::byte, 8> Buffer{};
                         std::error_code ec;
                         const auto n = co_await a->AsyncReadSome(Buffer, ec);
                         EXPECT_EQ(n, 0U);
                         EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                         *read_done = true;
                     };
                     auto on_error = [read_done, child_ep](const std::exception_ptr &ep)
                     {
                         *child_ep = ep;
                         *read_done = true;
                     };
                     net::co_spawn(a->Executor(), std::move(AsyncRead), std::move(on_error));
                     net::steady_timer Wait(a->Executor());
                     Wait.expires_after(std::chrono::milliseconds(50));
                     co_await Wait.async_wait(net::use_awaitable);
                 });

        ASSERT_FALSE(*child_ep);
        EXPECT_TRUE(*read_done);
    }

    // ══════════════ T0-3 超时语义（Transmission 虚接口） ══════════════

    TEST(Transport, AsyncReadTimeoutError)
    {
        // AsyncReadSome 超时 → operation_timed_out 错误
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     a.SetTimeout(std::chrono::milliseconds(30));
                     std::array<std::byte, 16> buf{};
                     std::error_code ec;
                     const auto n = co_await a.AsyncReadSome(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                 });
    }

    TEST(Transport, AsyncReadTimeoutDisabled)
    {
        // SetTimeout(0) 禁用 → 挂起直到数据到达
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     a.SetTimeout(std::chrono::milliseconds(0));
                     auto writer = [&]() -> net::awaitable<void>
                     {
                         std::array<std::byte, 4> Data{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
                         co_await net::post(a.Executor(), net::use_awaitable);
                         co_await net::post(a.Executor(), net::use_awaitable);
                         std::error_code wec;
                         co_await b.AsyncWriteSome(Data, wec);
                     };
                     net::co_spawn(a.Executor(), writer(), net::detached);
                     std::array<std::byte, 16> buf{};
                     std::error_code ec;
                     const auto n = co_await a.AsyncReadSome(buf, ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_FALSE(ec);
                 });
    }

    TEST(Transport, InterfaceTransmissionLike)
    {
        // Transmission 派生类满足扩展 concept（Shutdown/SetTimeout/IsOpen）
        static_assert(Preview::TransmissionLike<Preview::MemoryStream>);
        static_assert(Preview::TransmissionLike<Preview::Transport::Reliable>);
    }

    TEST(Transport, InterfaceIsOpen)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        EXPECT_TRUE(a.IsOpen());
        a.Close();
        EXPECT_FALSE(a.IsOpen());
    }

    TEST(Transport, InterfaceShutdownEof)
    {
        // 通过虚接口多态调用 Shutdown：对端读 EOF
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Preview::Transmission &ref = a;
        ref.Shutdown();
        std::array<std::uint8_t, 8> buf{};
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto n = co_await b.ReadSome(buf);
                     EXPECT_EQ(n, 0u);
                 });
    }

    TEST(Transport, InterfaceSetTimeoutPolymorphic)
    {
        // 通过基类指针设置超时 → 读超时错误
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Preview::Transmission *base = &a;
        base->SetTimeout(std::chrono::milliseconds(20));
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto n = co_await a.AsyncReadSome(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, std::make_error_code(std::errc::timed_out));
                 });
    }

} // namespace
