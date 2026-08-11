/**
 * @file HttpClientServerPerf.cpp
 * @brief HTTP 代理会话测试（CONNECT 隧道 + 传输 + 性能）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/http/http.hpp>

namespace
{
    using namespace psmtest;
    namespace net = boost::asio;

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

    auto make_dst() -> http::address
    {
        http::address dst{};
        dst.host = "93.184.216.34";
        dst.port = 443;
        return dst;
    }

    TEST(HttpClientServer, TunnelAndTransfer100MB)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        http::client cl(http::client_config{});
        http::server sv(http::server_config{});

        constexpr std::size_t kTotal = 100 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                http::address req{};
                auto s = co_await sv.accept(std::make_shared<memory_stream>(std::move(b)), req);
                if (!s)
                {
                    EXPECT_TRUE(false) << "accept failed";
                    co_return;
                }
                EXPECT_EQ(req.port, 443u);
                std::array<std::uint8_t, kBlock> buf{};
                std::size_t got = 0;
                while (got < kTotal)
                {
                    const auto n = co_await s->read_some(buf);
                    if (n == 0)
                        break;
                    got += n;
                }
                EXPECT_EQ(got, kTotal);
                co_await s->close();
            };
            net::co_spawn(b.executor(), server_coro(), net::detached);

            auto s = co_await cl.connect(std::make_shared<memory_stream>(std::move(a)), make_dst());
            if (!s)
            {
                EXPECT_TRUE(false) << "connect failed";
                co_return;
            }
            std::vector<std::uint8_t> payload(kBlock, 0x48);
            std::size_t sent = 0;
            while (sent < kTotal)
            {
                const auto n = std::min(kBlock, kTotal - sent);
                (void)co_await s->write_all(
                    std::span<const std::uint8_t>(payload.data(), n));
                sent += n;
            }
            EXPECT_EQ(sent, kTotal);
            co_await s->close(); });
    }

    TEST(HttpClientServer, ThroughputLatency)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        http::client cl(http::client_config{});
        http::server sv(http::server_config{});

        bench_report tp{};
        bench_report lat{};
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                http::address req{};
                auto s = co_await sv.accept(std::make_shared<memory_stream>(std::move(b)), req);
                if (!s)
                    co_return;
                std::array<std::uint8_t, 128 * 1024> buf{};
                while (true)
                {
                    const auto n = co_await s->read_some(buf);
                    if (n == 0)
                        break;
                    (void)co_await s->write_all(
                        std::span<const std::uint8_t>(buf.data(), n));
                }
                co_await s->close();
            };
            net::co_spawn(b.executor(), server_coro(), net::detached);

            auto s = co_await cl.connect(std::make_shared<memory_stream>(std::move(a)), make_dst());
            if (!s)
                co_return;
            bench_options opt;
            opt.total = 64 * 1024 * 1024;
            opt.block = 64 * 1024;
            tp = co_await bench_throughput(*s, *s, opt);
            // 延迟用新连接（回环小包 RTT）
            auto [a2, b2] = make_memory_pair(ioc.get_executor());
            auto server_coro2 = [&]() -> net::awaitable<void>
            {
                http::address req{};
                auto s = co_await sv.accept(std::make_shared<memory_stream>(std::move(b2)), req);
                if (!s)
                    co_return;
                std::array<std::uint8_t, 128 * 1024> buf{};
                while (true)
                {
                    const auto n = co_await s->read_some(buf);
                    if (n == 0)
                        break;
                    (void)co_await s->write_all(
                        std::span<const std::uint8_t>(buf.data(), n));
                }
                co_await s->close();
            };
            net::co_spawn(b2.executor(), server_coro2(), net::detached);
            auto s2 = co_await cl.connect(std::make_shared<memory_stream>(std::move(a2)), make_dst());
            if (!s2)
                co_return;
            bench_options lopt;
            lopt.total = 1000 * 4 * 1024;
            lopt.block = 4 * 1024;
            lat = co_await bench_throughput(*s2, *s2, lopt);
            co_await s2->close(); });

        std::printf("http throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
                    tp.mbps, lat.latency_avg, lat.latency_p50, lat.latency_p95,
                    lat.latency_p99, lat.latency_min, lat.latency_max, lat.samples);
    }

} // namespace
