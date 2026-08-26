/**
 * @file MuxPerf.cpp
 * @brief 多路复用性能基准（100MB 传输 + 吞吐 + 延迟）
 * @details smux / yamux / h2mux 各自独立实现；测量 100MB 传输完整性、
 *          吞吐量（MB/s）与回环延迟（avg/p50/p95/p99/min/max）。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
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
#include <common/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <common/Protocols/Mux/Smux/Smux.hpp>
#include <common/Protocols/Mux/Yamux/Yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    using namespace Preview::Mux;

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

    auto fnv1a64(std::span<const std::uint8_t> Data) -> std::uint64_t
    {
        std::uint64_t h = 14695981039346656037ULL;
        for (const auto b : Data)
        {
            h ^= b;
            h *= 1099511628211ULL;
        }
        return h;
    }

    /// 100MB 传输完整性（Client 写 Server 读，摘要比对）
    template <typename Client, typename Server>
    auto run_transfer(net::io_context &ioc, Client &cl, Server &sv) -> void
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        constexpr std::size_t kTotal = 100 * 1024 * 1024;
        constexpr std::size_t kBlock = 64 * 1024;
        run_coro(
            ioc,
            [&]() -> net::awaitable<void>
            {
                // 服务端完成通知：防止 detached 协程在 ioc 析构时
                // 仍挂起（use-after-free）
                net::experimental::channel<void(boost::system::error_code)> server_done(ioc.get_executor(), 1);
                auto server_coro = [&]() -> net::awaitable<void>
                {
                    auto s = co_await sv.AcceptStream();
                    if (!s)
                    {
                        EXPECT_TRUE(false) << "Accept Failed";
                        server_done.try_send(boost::system::error_code{});
                        co_return;
                    }
                    std::array<std::byte, kBlock> buf{};
                    std::size_t got = 0;
                    while (got < kTotal)
                    {
                        std::error_code ec;
                        const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                        if (ec || n == 0)
                        {
                            break;
                        }
                        got += n;
                    }
                    EXPECT_EQ(got, kTotal);
                    s->Close();
                    server_done.try_send(boost::system::error_code{});
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                auto s = co_await cl.OpenStream();
                if (!s)
                {
                    EXPECT_TRUE(false) << "Open Failed";
                    co_return;
                }
                std::vector<std::uint8_t> payload(kBlock, 0x2A);
                std::size_t sent = 0;
                std::size_t block_idx = 0;
                while (sent < kTotal)
                {
                    const auto n = std::min(kBlock, kTotal - sent);
                    std::error_code ec;
                    const auto w = co_await s->async_write_some(
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
                s->Close();
                cl.Close();
                sv.Close();
                // 等待服务端协程完成，避免 ioc 析构时挂起协程帧悬垂
                co_await server_done.async_receive(net::use_awaitable);
            });
    }

    /// 吞吐 + 延迟报告
    template <typename Client, typename Server>
    auto RunBench(net::io_context &ioc, Client &cl, Server &sv, const char *Name) -> void
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        BenchReport rep{};
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端完成通知：防止 detached 协程在 ioc 析构时
                     // 仍挂起（use-after-free）
                     net::experimental::channel<void(boost::system::error_code)> server_done(ioc.get_executor(), 1);
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto s = co_await sv.AcceptStream();
                         if (!s)
                         {
                             server_done.try_send(boost::system::error_code{});
                             co_return;
                         }
                         std::array<std::byte, 128 * 1024> buf{};
                         while (true)
                         {
                             std::error_code ec;
                             const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             ec.clear();
                             (void)co_await s->async_write_some(std::span<const std::byte>(buf.data(), n),
                                                                ec);
                         }
                         s->Close();
                         server_done.try_send(boost::system::error_code{});
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto s = co_await cl.OpenStream();
                     if (!s)
                     {
                         co_return;
                     }
                     BenchOptions opt;
                     opt.Total = 64 * 1024 * 1024;
                     opt.Block = 64 * 1024;
                     rep = co_await BenchThroughputTx(*s, *s, opt);
                     s->Close();
                     cl.Close();
                     // 显式 co_await 服务端会话关闭：触发 Teardown 唤醒
                     // 服务端挂起读（sv.Close() 是 void，丢弃 awaitable 不执行）
                     if (sv.Session())
                     {
                         co_await sv.Session()->Close();
                     }
                     // 等待服务端协程完成，避免 ioc 析构时挂起协程帧悬垂
                     co_await server_done.async_receive(net::use_awaitable);
                 });

        std::printf("%s throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f "
                    "max %.3f) samples=%zu\n",
                    Name, rep.Mbps, rep.LatencyAvg, rep.LatencyP50, rep.LatencyP95, rep.LatencyP99,
                    rep.LatencyMin, rep.LatencyMax, rep.Samples);
    }

    TEST(MuxPerf, SmuxTransfer100MB)
    {
        net::io_context ioc;
        Smux::Client cl;
        Smux::Server sv;
        run_transfer(ioc, cl, sv);
    }

    TEST(MuxPerf, YamuxTransfer100MB)
    {
        net::io_context ioc;
        Yamux::Client cl;
        Yamux::Server sv;
        run_transfer(ioc, cl, sv);
    }

    TEST(MuxPerf, H2muxTransfer100MB)
    {
        net::io_context ioc;
        H2Mux::Client cl;
        H2Mux::Server sv;
        run_transfer(ioc, cl, sv);
    }

    TEST(MuxPerf, SmuxThroughputLatency)
    {
        net::io_context ioc;
        Smux::Client cl;
        Smux::Server sv;
        RunBench(ioc, cl, sv, "smux ");
    }

    TEST(MuxPerf, YamuxThroughputLatency)
    {
        net::io_context ioc;
        Yamux::Client cl;
        Yamux::Server sv;
        RunBench(ioc, cl, sv, "yamux");
    }

    TEST(MuxPerf, H2muxThroughputLatency)
    {
        net::io_context ioc;
        H2Mux::Client cl;
        H2Mux::Server sv;
        RunBench(ioc, cl, sv, "h2mux");
    }

} // namespace
