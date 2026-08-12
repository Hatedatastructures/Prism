/**
 * @file VmessClientServerPerf.cpp
 * @brief VMess 客户端/服务端封装测试（传输完整性 + 性能）
 * @details 覆盖：
 *          - 100MB / 1GB 传输完整性
 *          - 吞吐量（MB/s）
 *          - 回环延迟（avg/p50/p95/p99/min/max）
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
#include <common/proxy/vmess/vmess.hpp>

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

    auto make_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> u{};
        u.fill(0x42);
        return u;
    }

    auto make_dst() -> vmess::address
    {
        vmess::address dst{};
        dst.type = vmess::address_type::ipv4;
        dst.host = "93.184.216.34";
        dst.port = 443;
        return dst;
    }

    /// 传输完整性测试（client 写 server 读）
    auto run_transfer(net::io_context &ioc, const std::size_t total) -> void
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());

        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, msg, srv] = co_await vmess::accept(
                    std::make_shared<memory_stream>(std::move(b)), vmess::server_config{make_uuid()});
                if (err != error::none)
                {
                    EXPECT_TRUE(false) << "accept failed";
                    co_return;
                }
                EXPECT_EQ(msg.dst.port, 443u);
                std::array<std::byte, kBlock> buf{};
                std::size_t got = 0;
                while (got < total)
                {
                    std::error_code ec;
                    const auto n = co_await srv->async_read_some(buf, ec);
                    if (ec || n == 0)
                        break;
                    got += n;
                }
                EXPECT_EQ(got, total);
                srv->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto [herr, cli] = co_await vmess::connect(
                std::make_shared<memory_stream>(std::move(a)), vmess::client_config{make_uuid()}, make_dst());
            if (herr != error::none || !cli)
            {
                EXPECT_TRUE(false) << "connect failed";
                co_return;
            }
            std::vector<std::uint8_t> payload(kBlock, 0x5A);
            std::size_t sent = 0;
            std::size_t yield_cnt = 0;
            while (sent < total)
            {
                if ((++yield_cnt % 16) == 0)
                    co_await net::post(ioc.get_executor(), net::use_awaitable);
                const auto n = std::min(kBlock, total - sent);
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
            EXPECT_EQ(sent, total);
            cli->close(); });
    }

    TEST(VmessClientServer, Transfer100MB)
    {
        net::io_context ioc;
        run_transfer(ioc, 100 * 1024 * 1024);
    }

    TEST(VmessClientServer, Transfer1GB)
    {
        net::io_context ioc;
        run_transfer(ioc, 1024 * 1024 * 1024);
    }

    TEST(VmessClientServer, ThroughputLatency)
    {
        net::io_context ioc;
        auto [a1, b1] = make_memory_pair(ioc.get_executor());

        bench_report tp{};
        bench_report lat{};
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            // 连接 1：吞吐（回环服务端）
            auto server_coro1 = [&]() -> net::awaitable<void>
            {
                auto [err, msg, srv] = co_await vmess::accept(
                    std::make_shared<memory_stream>(std::move(b1)), vmess::server_config{make_uuid()});
                if (err != error::none)
                    co_return;
                std::array<std::byte, 128 * 1024> buf{};
                while (true)
                {
                    std::error_code ec;
                    const auto n = co_await srv->async_read_some(buf, ec);
                    if (ec || n == 0)
                        break;
                    co_await srv->async_write_some(std::span(buf.data(), n), ec);
                }
                srv->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro1(), net::detached);

            auto [herr, cli] = co_await vmess::connect(
                std::make_shared<memory_stream>(std::move(a1)), vmess::client_config{make_uuid()}, make_dst());
            if (herr != error::none || !cli)
                co_return;
            bench_options opt;
            opt.total = 64 * 1024 * 1024;
            opt.block = 64 * 1024;
            tp = co_await bench_throughput_tx(*cli, *cli, opt);
            cli->close();

            // 连接 2：延迟（回环小包 RTT）
            auto [a2, b2] = make_memory_pair(ioc.get_executor());
            auto server_coro2 = [&]() -> net::awaitable<void>
            {
                auto [err, msg, srv] = co_await vmess::accept(
                    std::make_shared<memory_stream>(std::move(b2)), vmess::server_config{make_uuid()});
                if (err != error::none)
                    co_return;
                std::array<std::byte, 128 * 1024> buf{};
                while (true)
                {
                    std::error_code ec;
                    const auto n = co_await srv->async_read_some(buf, ec);
                    if (ec || n == 0)
                        break;
                    co_await srv->async_write_some(std::span(buf.data(), n), ec);
                }
                srv->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro2(), net::detached);
            auto [herr2, cli2] = co_await vmess::connect(
                std::make_shared<memory_stream>(std::move(a2)), vmess::client_config{make_uuid()}, make_dst());
            if (herr2 != error::none || !cli2)
                co_return;
            bench_options lopt;
            lopt.total = 1000 * 4 * 1024;
            lopt.block = 4 * 1024;
            lat = co_await bench_throughput_tx(*cli2, *cli2, lopt);
            cli2->close(); });

        std::printf("vmess throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
                    tp.mbps, lat.latency_avg, lat.latency_p50, lat.latency_p95,
                    lat.latency_p99, lat.latency_min, lat.latency_max, lat.samples);
    }

} // namespace
