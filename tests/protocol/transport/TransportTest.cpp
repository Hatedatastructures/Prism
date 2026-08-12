/**
 * @file TransportTest.cpp
 * @brief 传输抽象测试（memory_stream / socket_stream / bench）
 * @details 验证：
 *          - memory_stream 双向数据一致与关闭语义
 *          - bench_throughput / bench_latency 统计正确
 *          - stream concept 约束生效
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <common/core/transport/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transport/stream.hpp>

namespace
{
    using namespace psmtest;

    /// 回环跑一个协程并返回异常（MuxLifecycle 模式）
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
            std::rethrow_exception(ep);
    }

    TEST(Transport, MemoryPairEcho)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            const std::string msg = "hello memory pipe";
            EXPECT_FALSE(co_await a.write_all(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size())));
            std::array<std::uint8_t, 64> buf{};
            const auto n = co_await b.read_some(buf);
            EXPECT_EQ(n, msg.size());
            EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), msg); });
    }

    TEST(Transport, MemoryPairCloseSemantics)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            a.close();
            // 对端读返回 0
            std::array<std::uint8_t, 8> buf{};
            const auto n = co_await b.read_some(buf);
            EXPECT_EQ(n, 0u);
            // 对端写返回 broken_pipe
            const auto ec = co_await b.write_all(buf);
            EXPECT_EQ(ec, net::error::broken_pipe); });
    }

    TEST(Transport, BenchThroughputMemory)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        bench_report r{};
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            bench_options opt;
            opt.total = 16 * 1024 * 1024; // 16MB
            opt.block = 64 * 1024;
            r = co_await bench_throughput(a, b, opt); });
        EXPECT_EQ(r.bytes, 16u * 1024u * 1024u);
        EXPECT_GT(r.mbps, 0.0);
    }

    TEST(Transport, ReadTimeout)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        bool timed_out = false;
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            std::array<std::uint8_t, 16> buf{};
            a.set_timeout(std::chrono::milliseconds(50));
            const auto t0 = std::chrono::steady_clock::now();
            const auto n = co_await a.read_some(buf);
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();
            EXPECT_EQ(n, 0u);
            EXPECT_GE(ms, 40);
            timed_out = true; });
        EXPECT_TRUE(timed_out);
    }

    TEST(Transport, ShutdownSemantics)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            co_await a.shutdown();
            // 对端读返回 0（半关）
            std::array<std::uint8_t, 8> buf{};
            const auto n = co_await b.read_some(buf);
            EXPECT_EQ(n, 0u);
            // 半关后本端仍可读对端数据
            const auto wec = co_await b.write_all(buf);
            EXPECT_FALSE(wec);
            std::array<std::uint8_t, 8> buf2{};
            const auto n2 = co_await a.read_some(buf2);
            EXPECT_EQ(n2, 8u); });
    }

    TEST(Transport, CancelSemantics)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto reader = [&]() -> net::awaitable<void>
            {
                std::array<std::uint8_t, 8> buf{};
                const auto n = co_await a.read_some(buf);
                EXPECT_EQ(n, 0u);
            };
            net::co_spawn(a.executor(), reader(), net::detached);
            // 让 reader 先挂起
            co_await net::post(a.executor(), net::use_awaitable);
            co_await net::post(a.executor(), net::use_awaitable);
            a.cancel(); });
    }

} // namespace
