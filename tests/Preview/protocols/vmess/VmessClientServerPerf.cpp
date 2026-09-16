/**
 * @file VmessClientServerPerf.cpp
 * @brief VMess 客户端/服务端封装测试（传输完整性 + 性能）
 * @details 覆盖：
 *          - 100MB / 1GB 传输完整性
 *          - 吞吐量（MB/s）
 *          - 回环延迟（avg/p50/p95/p99/min/max）
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Vmess = Preview::Vmess;
    using Preview::AsBytes;
    using Preview::BenchOptions;
    using Preview::BenchReport;
    using Preview::BenchThroughputTx;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        Uuid.fill(0x42);
        return Uuid;
    }

    auto MakeDestination() -> Vmess::Address
    {
        Vmess::Address Destination{};
        Destination.Type = Vmess::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    /// 传输完整性测试（Client 写 Server 读）
    auto RunTransfer(Net::io_context &IoContext, const std::size_t Total) -> void
    {
        auto [a, b] = MakeMemoryPair(IoContext.get_executor());

        constexpr std::size_t kBlock = 64 * 1024;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, msg, srv] =
                             co_await Vmess::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                    Vmess::ServerConfig{MakeUuid()});
                         if (err != Error::None)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         EXPECT_EQ(msg.dst.Port, 443u);
                         std::array<std::byte, kBlock> buf{};
                         std::size_t got = 0;
                         while (got < Total)
                         {
                             std::error_code ec;
                             const auto n = co_await srv->async_read_some(buf, ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             got += n;
                         }
                         EXPECT_EQ(got, Total);
                         srv->Close();
                     };
                    Net::co_spawn(IoContext.get_executor(), server_coro(), Net::detached);

                     auto [herr, cli] =
                         co_await Vmess::Connect(std::make_shared<MemoryStream>(std::move(a)),
                                                 Vmess::ClientConfig{MakeUuid()}, MakeDestination());
                     if (herr != Error::None || !cli)
                     {
                         EXPECT_TRUE(false) << "Connect Failed";
                         co_return;
                     }
                     std::vector<std::uint8_t> payload(kBlock, 0x5A);
                     std::size_t sent = 0;
                     std::size_t yield_cnt = 0;
                     while (sent < Total)
                     {
                         if ((++yield_cnt % 16) == 0)
                         {
                             co_await Net::post(IoContext.get_executor(), Net::use_awaitable);
                         }
                         const auto n = std::min(kBlock, Total - sent);
                         std::size_t Done = 0;
                         while (Done < n)
                         {
                             std::error_code ec;
                             const auto w = co_await cli->async_write_some(
                                 std::span<const std::byte>(
                                     reinterpret_cast<const std::byte *>(payload.data() + Done), n - Done),
                                 ec);
                             if (ec || w == 0)
                             {
                                 break;
                             }
                             Done += w;
                         }
                         if (Done < n)
                         {
                             break;
                         }
                         sent += n;
                     }
                     EXPECT_EQ(sent, Total);
                     cli->Close();
                 });
    }

    TEST(VmessClientServer, Transfer100MB)
    {
        Net::io_context ioc;
        RunTransfer(ioc, 100 * 1024 * 1024);
    }

    TEST(VmessClientServer, Transfer1GB)
    {
        Net::io_context ioc;
        RunTransfer(ioc, 1024 * 1024 * 1024);
    }

    TEST(VmessClientServer, ThroughputLatency)
    {
        Net::io_context ioc;
        auto [a1, b1] = MakeMemoryPair(ioc.get_executor());

        BenchReport tp{};
        BenchReport lat{};
        RunCoroutine(
            ioc,
            [&]() -> Net::awaitable<void>
            {
                // 连接 1：吞吐（回环服务端）
                auto server_coro1 = [&]() -> Net::awaitable<void>
                {
                    auto [err, msg, srv] = co_await Vmess::Accept(
                        std::make_shared<MemoryStream>(std::move(b1)), Vmess::ServerConfig{MakeUuid()});
                    if (err != Error::None)
                    {
                        co_return;
                    }
                    std::array<std::byte, 128 * 1024> buf{};
                    while (true)
                    {
                        std::error_code ec;
                        const auto n = co_await srv->async_read_some(buf, ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        co_await srv->async_write_some(std::span(buf.data(), n), ec);
                    }
                    srv->Close();
                };
                Net::co_spawn(ioc.get_executor(), server_coro1(), Net::detached);

                auto [herr, cli] = co_await Vmess::Connect(std::make_shared<MemoryStream>(std::move(a1)),
                                                           Vmess::ClientConfig{MakeUuid()}, MakeDestination());
                if (herr != Error::None || !cli)
                {
                    co_return;
                }
                BenchOptions opt;
                opt.Total = 64 * 1024 * 1024;
                opt.Block = 64 * 1024;
                tp = co_await BenchThroughputTx(*cli, *cli, opt);
                cli->Close();

                // 连接 2：延迟（回环小包 RTT）
                auto [a2, b2] = MakeMemoryPair(ioc.get_executor());
                auto server_coro2 = [&]() -> Net::awaitable<void>
                {
                    auto [err, msg, srv] = co_await Vmess::Accept(
                        std::make_shared<MemoryStream>(std::move(b2)), Vmess::ServerConfig{MakeUuid()});
                    if (err != Error::None)
                    {
                        co_return;
                    }
                    std::array<std::byte, 128 * 1024> buf{};
                    while (true)
                    {
                        std::error_code ec;
                        const auto n = co_await srv->async_read_some(buf, ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        co_await srv->async_write_some(std::span(buf.data(), n), ec);
                    }
                    srv->Close();
                };
                Net::co_spawn(ioc.get_executor(), server_coro2(), Net::detached);
                auto [herr2, cli2] = co_await Vmess::Connect(std::make_shared<MemoryStream>(std::move(a2)),
                                                             Vmess::ClientConfig{MakeUuid()}, MakeDestination());
                if (herr2 != Error::None || !cli2)
                {
                    co_return;
                }
                BenchOptions lopt;
                lopt.Total = 1000 * 4 * 1024;
                lopt.Block = 4 * 1024;
                lat = co_await BenchThroughputTx(*cli2, *cli2, lopt);
                cli2->Close();
            });

        std::printf("vmess throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min "
                    "%.3f max %.3f) samples=%zu\n",
                    tp.Mbps, lat.LatencyAvg, lat.LatencyP50, lat.LatencyP95, lat.LatencyP99,
                    lat.LatencyMin, lat.LatencyMax, lat.Samples);
    }

} // namespace
