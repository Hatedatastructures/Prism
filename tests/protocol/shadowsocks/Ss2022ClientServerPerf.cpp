/**
 * @file Ss2022ClientServerPerf.cpp
 * @brief SS2022 客户端/服务端封装测试（握手 + 传输 + 性能）
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/shadowsocks2022/shadowsocks2022.hpp>

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

    auto make_dst() -> ss2022::address
    {
        ss2022::address dst{};
        dst.type = ss2022::address_type::ipv4;
        dst.host = "93.184.216.34";
        dst.port = 443;
        return dst;
    }

    TEST(Ss2022ClientServer, HandshakeAndTransfer100MB)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        constexpr std::size_t kTotal = 100 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, srv] = co_await psmtest::shadowsocks2022::accept(
                    std::make_shared<memory_stream>(std::move(b)),
                    psmtest::shadowsocks2022::server_config{"perf-secret"});
                if (err != error::none)
                {
                    EXPECT_TRUE(false) << "handshake failed";
                    co_return;
                }
                EXPECT_EQ(req.dst.port, 443u);
                std::array<std::byte, kBlock> buf{};
                std::size_t got = 0;
                while (got < kTotal)
                {
                    std::error_code ec;
                    const auto n = co_await srv->async_read_some(std::span<std::byte>(buf), ec);
                    if (ec || n == 0)
                        break;
                    got += n;
                }
                EXPECT_EQ(got, kTotal);
                srv->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto [cerr, cli] = co_await psmtest::shadowsocks2022::connect(
                std::make_shared<memory_stream>(std::move(a)),
                psmtest::shadowsocks2022::client_config{"perf-secret"}, make_dst());
            if (cerr != error::none)
            {
                EXPECT_TRUE(false) << "connect failed";
                co_return;
            }
            std::vector<std::uint8_t> payload(kBlock, 0x6E);
            std::size_t sent = 0;
            std::size_t block_idx = 0;
            while (sent < kTotal)
            {
                const auto n = std::min(kBlock, kTotal - sent);
                std::error_code ec;
                const auto w = co_await cli->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(payload.data()), n), ec);
                if (ec || w == 0)
                    break;
                sent += w;
                // 让出调度：memory_stream 写同步完成，不 yield 会饿死对端协程
                if ((++block_idx & 0x0F) == 0)
                    co_await net::post(ioc.get_executor(), net::use_awaitable);
            }
            EXPECT_EQ(sent, kTotal);
            cli->close(); });
    }

    TEST(Ss2022ClientServer, ThroughputLatency)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        bench_report tp{};
        bench_report lat{};
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            auto server_coro = [&]() -> net::awaitable<void>
            {
                auto [err, req, srv] = co_await psmtest::shadowsocks2022::accept(
                    std::make_shared<memory_stream>(std::move(b)),
                    psmtest::shadowsocks2022::server_config{"perf-secret"});
                if (err != error::none)
                    co_return;
                std::array<std::byte, 128 * 1024> buf{};
                while (true)
                {
                    std::error_code ec;
                    const auto n = co_await srv->async_read_some(std::span<std::byte>(buf), ec);
                    if (ec || n == 0)
                        break;
                    ec.clear();
                    (void)co_await srv->async_write_some(
                        std::span<const std::byte>(buf.data(), n), ec);
                }
                srv->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

            auto [err, cli] = co_await psmtest::shadowsocks2022::connect(
                std::make_shared<memory_stream>(std::move(a)),
                psmtest::shadowsocks2022::client_config{"perf-secret"}, make_dst());
            if (err != error::none || !cli)
                co_return;
            bench_options opt;
            opt.total = 64 * 1024 * 1024;
            opt.block = 64 * 1024;
            tp = co_await bench_throughput_tx(*cli, *cli, opt);
            // 延迟用新连接（回环小包 RTT）
            auto [a2, b2] = make_memory_pair(ioc.get_executor());
            auto server_coro2 = [&]() -> net::awaitable<void>
            {
                auto [err, req, srv2] = co_await psmtest::shadowsocks2022::accept(
                    std::make_shared<memory_stream>(std::move(b2)),
                    psmtest::shadowsocks2022::server_config{"perf-secret"});
                if (err != error::none)
                    co_return;
                std::array<std::byte, 128 * 1024> buf{};
                while (true)
                {
                    std::error_code ec;
                    const auto n = co_await srv2->async_read_some(std::span<std::byte>(buf), ec);
                    if (ec || n == 0)
                        break;
                    ec.clear();
                    (void)co_await srv2->async_write_some(
                        std::span<const std::byte>(buf.data(), n), ec);
                }
                srv2->close();
            };
            net::co_spawn(ioc.get_executor(), server_coro2(), net::detached);
            auto [err2, cli2] = co_await psmtest::shadowsocks2022::connect(
                std::make_shared<memory_stream>(std::move(a2)),
                psmtest::shadowsocks2022::client_config{"perf-secret"}, make_dst());
            if (err2 != error::none || !cli2)
                co_return;
            bench_options lopt;
            lopt.total = 1000 * 4 * 1024;
            lopt.block = 4 * 1024;
            lat = co_await bench_throughput_tx(*cli2, *cli2, lopt);
            cli2->close(); });

        std::printf("ss2022 throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f max %.3f) samples=%zu\n",
                    tp.mbps, lat.latency_avg, lat.latency_p50, lat.latency_p95,
                    lat.latency_p99, lat.latency_min, lat.latency_max, lat.samples);
    }

} // namespace
