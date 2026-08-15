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

#include <common/core/transport/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/mux/h2mux/h2mux.hpp>
#include <common/mux/smux/smux.hpp>
#include <common/mux/yamux/yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    using namespace psmtest::mux;

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

    auto fnv1a64(std::span<const std::uint8_t> data) -> std::uint64_t
    {
        std::uint64_t h = 14695981039346656037ULL;
        for (const auto b : data)
        {
            h ^= b;
            h *= 1099511628211ULL;
        }
        return h;
    }

    /// 100MB 传输完整性（client 写 server 读，摘要比对）
    template <typename Client, typename Server>
    auto run_transfer(net::io_context &ioc, Client &cl, Server &sv) -> void
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        ASSERT_TRUE(cl.connect(std::make_shared<memory_stream>(std::move(a))));
        ASSERT_TRUE(sv.accept(std::make_shared<memory_stream>(std::move(b))));

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
                    auto s = co_await sv.accept_stream();
                    if (!s)
                    {
                        EXPECT_TRUE(false) << "accept failed";
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
                    s->close();
                    server_done.try_send(boost::system::error_code{});
                };
                net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                auto s = co_await cl.open_stream();
                if (!s)
                {
                    EXPECT_TRUE(false) << "open failed";
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
                    // 让出调度：memory_stream 写同步完成，不 yield 会饿死对端协程
                    if ((++block_idx & 0x0F) == 0)
                    {
                        co_await net::post(ioc.get_executor(), net::use_awaitable);
                    }
                }
                EXPECT_EQ(sent, kTotal);
                s->close();
                cl.close();
                sv.close();
                // 等待服务端协程完成，避免 ioc 析构时挂起协程帧悬垂
                co_await server_done.async_receive(net::use_awaitable);
            });
    }

    /// 吞吐 + 延迟报告
    template <typename Client, typename Server>
    auto run_bench(net::io_context &ioc, Client &cl, Server &sv, const char *name) -> void
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        ASSERT_TRUE(cl.connect(std::make_shared<memory_stream>(std::move(a))));
        ASSERT_TRUE(sv.accept(std::make_shared<memory_stream>(std::move(b))));

        bench_report rep{};
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 服务端完成通知：防止 detached 协程在 ioc 析构时
                     // 仍挂起（use-after-free）
                     net::experimental::channel<void(boost::system::error_code)> server_done(ioc.get_executor(), 1);
                     auto server_coro = [&]() -> net::awaitable<void>
                     {
                         auto s = co_await sv.accept_stream();
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
                         s->close();
                         server_done.try_send(boost::system::error_code{});
                     };
                     net::co_spawn(ioc.get_executor(), server_coro(), net::detached);

                     auto s = co_await cl.open_stream();
                     if (!s)
                     {
                         co_return;
                     }
                     bench_options opt;
                     opt.total = 64 * 1024 * 1024;
                     opt.block = 64 * 1024;
                     rep = co_await bench_throughput_tx(*s, *s, opt);
                     s->close();
                     cl.close();
                     // 显式 co_await 服务端会话关闭：触发 teardown 唤醒
                     // 服务端挂起读（sv.close() 是 void，丢弃 awaitable 不执行）
                     if (sv.session())
                     {
                         co_await sv.session()->close();
                     }
                     // 等待服务端协程完成，避免 ioc 析构时挂起协程帧悬垂
                     co_await server_done.async_receive(net::use_awaitable);
                 });

        std::printf("%s throughput: %.1f MB/s | latency(ms): avg %.3f p50 %.3f p95 %.3f p99 %.3f (min %.3f "
                    "max %.3f) samples=%zu\n",
                    name, rep.mbps, rep.latency_avg, rep.latency_p50, rep.latency_p95, rep.latency_p99,
                    rep.latency_min, rep.latency_max, rep.samples);
    }

    TEST(MuxPerf, SmuxTransfer100MB)
    {
        net::io_context ioc;
        smux::client cl;
        smux::server sv;
        run_transfer(ioc, cl, sv);
    }

    TEST(MuxPerf, YamuxTransfer100MB)
    {
        net::io_context ioc;
        yamux::client cl;
        yamux::server sv;
        run_transfer(ioc, cl, sv);
    }

    TEST(MuxPerf, H2muxTransfer100MB)
    {
        net::io_context ioc;
        h2mux::client cl;
        h2mux::server sv;
        run_transfer(ioc, cl, sv);
    }

    TEST(MuxPerf, SmuxThroughputLatency)
    {
        net::io_context ioc;
        smux::client cl;
        smux::server sv;
        run_bench(ioc, cl, sv, "smux ");
    }

    TEST(MuxPerf, YamuxThroughputLatency)
    {
        net::io_context ioc;
        yamux::client cl;
        yamux::server sv;
        run_bench(ioc, cl, sv, "yamux");
    }

    TEST(MuxPerf, H2muxThroughputLatency)
    {
        net::io_context ioc;
        h2mux::client cl;
        h2mux::server sv;
        run_bench(ioc, cl, sv, "h2mux");
    }

} // namespace
