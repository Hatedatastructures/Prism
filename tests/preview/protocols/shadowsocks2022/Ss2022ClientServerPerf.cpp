/**
 * @file Ss2022ClientServerPerf.cpp
 * @brief SS2022 客户端/服务端封装测试（握手 + 传输 + 性能）
 */

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

#include <common/Bench/Bench.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

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

    auto make_dst() -> Shadowsocks2022::Address
    {
        Shadowsocks2022::Address dst{};
        dst.Type = Shadowsocks2022::AddressType::Ipv4;
        dst.Host = "93.184.216.34";
        dst.Port = 443;
        return dst;
    }

    TEST(Ss2022ClientServer, HandshakeAndTransfer100MB)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        constexpr std::size_t kTotal = 100 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto [err, req, srv] = co_await Preview::Shadowsocks2022::Accept(
                        std::make_shared<MemoryStream>(std::move(b)),
                        Preview::Shadowsocks2022::ServerConfig{"perf-Secret"});
                    if (err != Error::None)
                    {
                        EXPECT_TRUE(false) << "handshake Failed";
                        co_return;
                    }
                    EXPECT_EQ(req.dst.Port, 443u);
                    std::array<std::byte, kBlock> buf{};
                    std::size_t got = 0;
                    while (got < kTotal)
                    {
                        std::error_code ec;
                        const auto n = co_await srv->async_read_some(std::span<std::byte>(buf), ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        got += n;
                    }
                    EXPECT_EQ(got, kTotal);
                    srv->Close();
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                auto [cerr, cli] = co_await Preview::Shadowsocks2022::Connect(
                    std::make_shared<MemoryStream>(std::move(a)),
                    Preview::Shadowsocks2022::ClientConfig{"perf-Secret"}, make_dst());
                if (cerr != Error::None)
                {
                    EXPECT_TRUE(false) << "Connect Failed";
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
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), n),
                        ec);
                    if (ec || w == 0)
                    {
                        break;
                    }
                    sent += w;
                    // 让出调度：MemoryStream 写同步完成，不 yield 会饿死对端协程
                    if ((++block_idx & 0x0F) == 0)
                    {
                        co_await net::post(ioc.get_executor(), net::use_awaitable);
                    }
                }
                EXPECT_EQ(sent, kTotal);
                cli->Close();
            });
    }

    TEST(Ss2022ClientServer, ThroughputLatency)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        BenchReport tp{};
        BenchReport lat{};
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto [err, req, srv] = co_await Preview::Shadowsocks2022::Accept(
                        std::make_shared<MemoryStream>(std::move(b)),
                        Preview::Shadowsocks2022::ServerConfig{"perf-Secret"});
                    if (err != Error::None)
                    {
                        co_return;
                    }
                    std::array<std::byte, 128 * 1024> buf{};
                    while (true)
                    {
                        std::error_code ec;
                        const auto n = co_await srv->async_read_some(std::span<std::byte>(buf), ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        ec.clear();
                        (void)co_await srv->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                    }
                    srv->Close();
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                auto [err, cli] = co_await Preview::Shadowsocks2022::Connect(
                    std::make_shared<MemoryStream>(std::move(a)),
                    Preview::Shadowsocks2022::ClientConfig{"perf-Secret"}, make_dst());
                if (err != Error::None || !cli)
                {
                    co_return;
                }
                BenchOptions opt;
                opt.Total = 64 * 1024 * 1024;
                opt.Block = 64 * 1024;
                tp = co_await BenchThroughputTx(*cli, *cli, opt);
                // 延迟用新连接（回环小包 RTT）
                auto [a2, b2] = MakeMemoryPair(ioc.get_executor());
                auto server_coro2 = [&]() -> net::awaitable<void>
                {
                    auto [err, req, srv2] = co_await Preview::Shadowsocks2022::Accept(
                        std::make_shared<MemoryStream>(std::move(b2)),
                        Preview::Shadowsocks2022::ServerConfig{"perf-Secret"});
                    if (err != Error::None)
                    {
                        co_return;
                    }
                    std::array<std::byte, 128 * 1024> buf{};
                    while (true)
                    {
                        std::error_code ec;
                        const auto n = co_await srv2->async_read_some(std::span<std::byte>(buf), ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        ec.clear();
                        (void)co_await srv2->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                    }
                    srv2->Close();
                };
                net::co_spawn(ioc.get_executor(), server_coro2(), net::detached);
                auto [err2, cli2] = co_await Preview::Shadowsocks2022::Connect(
                    std::make_shared<MemoryStream>(std::move(a2)),
                    Preview::Shadowsocks2022::ClientConfig{"perf-Secret"}, make_dst());
                if (err2 != Error::None || !cli2)
                {
                    co_return;
                }
                BenchOptions lopt;
                lopt.Total = 1000 * 4 * 1024;
                lopt.Block = 4 * 1024;
                lat = co_await BenchThroughputTx(*cli2, *cli2, lopt);
                cli2->Close();
            });

        std::printf("ss2022 throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min "
                    "%.3f max %.3f) samples=%zu\n",
                    tp.Mbps, lat.LatencyAvg, lat.LatencyP50, lat.LatencyP95, lat.LatencyP99,
                    lat.LatencyMin, lat.LatencyMax, lat.Samples);
    }

} // namespace
