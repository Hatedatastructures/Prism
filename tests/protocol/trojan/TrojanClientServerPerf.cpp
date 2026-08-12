/**
 * @file TrojanClientServerPerf.cpp
 * @brief Trojan 客户端/服务端封装测试（传输 + 性能）
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
#include <common/trojan/trojan.hpp>

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

    auto make_dst() -> trojan::address
    {
        trojan::address dst{};
        dst.type = trojan::address_type::ipv4;
        dst.host = "93.184.216.34";
        dst.port = 443;
        return dst;
    }

    TEST(TrojanClientServer, Transfer100MB)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        constexpr std::size_t kTotal = 100 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)), trojan::server_config{"pw123456"});
                if (err != error::none)
                {
                    EXPECT_TRUE(false) << "accept failed";
                    co_return;
                }
                EXPECT_EQ(req.target.port, 443u);
                std::array<std::byte, kBlock> buf{};
                std::size_t got = 0;
                while (got < kTotal)
                {
                    std::error_code ec;
                    const auto n = co_await conn->async_read_some(buf, ec);
                    if (ec || n == 0)
                        break;
                    got += n;
                }
                EXPECT_EQ(got, kTotal);
                conn->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto [herr, cli] = co_await trojan::connect(std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"pw123456"}, make_dst());
            if (herr != error::none || !cli)
            {
                EXPECT_TRUE(false) << "connect failed";
                co_return;
            }
            std::vector<std::uint8_t> payload(kBlock, 0x4D);
            std::size_t sent = 0;
            std::size_t yield_cnt = 0;
            while (sent < kTotal)
            {
                if ((++yield_cnt % 16) == 0)
                    co_await net::post(ioc.get_executor(), net::use_awaitable);
                const auto n = std::min(kBlock, kTotal - sent);
                std::size_t done = 0;
                while (done < n)
                {
                    std::error_code ec;
                    const auto w = co_await cli->async_write_some(
                        std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(payload.data() + done), n - done),
                        ec);
                    if (ec || w == 0)
                        break;
                    done += w;
                }
                if (done < n)
                    break;
                sent += n;
            }
            EXPECT_EQ(sent, kTotal);
            cli->close(); });
    }

    TEST(TrojanClientServer, ThroughputLatency)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        bench_report tp{};
        bench_report lat{};
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await trojan::accept(std::make_shared<memory_stream>(std::move(b)), trojan::server_config{"pw123456"});
                if (err != error::none)
                    co_return;
                std::array<std::byte, 128 * 1024> buf{};
                while (true)
                {
                    std::error_code ec;
                    const auto n = co_await conn->async_read_some(buf, ec);
                    if (ec || n == 0)
                        break;
                    co_await conn->async_write_some(std::span(buf.data(), n), ec);
                }
                conn->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto [herr, cli] = co_await trojan::connect(std::make_shared<memory_stream>(std::move(a)), trojan::client_config{"pw123456"}, make_dst());
            if (herr != error::none || !cli)
                co_return;
            bench_options opt;
            opt.total = 64 * 1024 * 1024;
            opt.block = 64 * 1024;
            tp = co_await bench_throughput_tx(*cli, *cli, opt);
            // 延迟用新连接（回环小包 RTT）
            auto [a2, b2] = make_memory_pair(ioc.get_executor());
            auto server_coro2 = [&]() -> net::awaitable<void>
            {
                auto [err, req, conn] = co_await trojan::accept(std::make_shared<memory_stream>(std::move(b2)), trojan::server_config{"pw123456"});
                if (err != error::none)
                    co_return;
                std::array<std::byte, 128 * 1024> buf{};
                while (true)
                {
                    std::error_code ec;
                    const auto n = co_await conn->async_read_some(buf, ec);
                    if (ec || n == 0)
                        break;
                    co_await conn->async_write_some(std::span(buf.data(), n), ec);
                }
                conn->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro2(), net::detached);
            auto [herr2, cli2] = co_await trojan::connect(std::make_shared<memory_stream>(std::move(a2)), trojan::client_config{"pw123456"}, make_dst());
            if (herr2 != error::none || !cli2)
                co_return;
            bench_options lopt;
            lopt.total = 1000 * 4 * 1024;
            lopt.block = 4 * 1024;
            lat = co_await bench_throughput_tx(*cli2, *cli2, lopt);
            cli2->close(); });

        std::printf("trojan throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
                    tp.mbps, lat.latency_avg, lat.latency_p50, lat.latency_p95,
                    lat.latency_p99, lat.latency_min, lat.latency_max, lat.samples);
    }

} // namespace
