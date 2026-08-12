/**
 * @file MuxTunnelStress.cpp
 * @brief 多路复用端到端压力测试
 * @details 控制变量法：变量 = 复用器(smux/yamux/h2mux) × 流数(1/8/32) × 块大小。
 * 使用内存管道对承载复用会话，多流并发传输，
 * 测量聚合吞吐（MB/s）与回环延迟（us），验证多路复用的并发收益与开销。
 */

#include <prism/foundation/memory/pool.hpp>

#include <common/core/transport/bench.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transport/stream.hpp>
#include <common/mux/smux/client.hpp>
#include <common/mux/smux/server.hpp>
#include <common/mux/yamux/client.hpp>
#include <common/mux/yamux/server.hpp>
#include <common/mux/h2mux/client.hpp>
#include <common/mux/h2mux/server.hpp>

#include <boost/asio.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace net = boost::asio;
namespace memory = psm::memory;
using namespace psmtest;

namespace
{

    /**
     * @brief 场景定义
     */
    struct mux_scenario
    {
        std::string name;             ///< 场景名称
        std::string muxer;            ///< 复用器类型
        std::size_t streams{8};       ///< 并发流数
        std::size_t block{65536};     ///< 块大小
        std::size_t per_stream{32ULL * 1024 * 1024}; ///< 每流传输量
    };

    /**
     * @brief 结果
     */
    struct mux_result
    {
        double mbps{0};
        double avg_us{0};
        double p50_us{0};
        double p95_us{0};
        double p99_us{0};
        std::size_t errors{0};
        bool pass{false};
    };

    /**
     * @brief 通用复用器运行器
     */
    template <typename Client, typename Server>
    auto run_mux_case(net::io_context &ioc, Client &cl, Server &sv, const mux_scenario &sc)
        -> net::awaitable<mux_result>
    {
        mux_result result{};
        auto [client_raw, server_raw] = make_memory_pair(ioc.get_executor());
        if (!cl.connect(std::make_shared<memory_stream>(std::move(client_raw))))
            co_return result;
        if (!sv.accept(std::make_shared<memory_stream>(std::move(server_raw))))
            co_return result;

        // 服务端：接受 N 流并回显（每流独立回显协程，流对象由协程自持）
        net::co_spawn(ioc.get_executor(), [&]() -> net::awaitable<void>
                      {
            for (std::size_t i = 0; i < sc.streams; ++i)
            {
                auto s = co_await sv.accept_stream();
                if (!s)
                    co_return;
                net::co_spawn(ioc.get_executor(), [s]() -> net::awaitable<void>
                              {
                    std::array<std::byte, 131072> buf{};
                    while (true)
                    {
                        std::error_code ec;
                        const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                        if (ec || n == 0)
                            break;
                        ec.clear();
                        (void)co_await s->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                    }
                    s->close(); }, net::detached);
            } }, net::detached);

        // 客户端：N 流并发打开并独立 bench（流对象由协程自持）
        std::vector<bench_report> reports(sc.streams);
        std::atomic<std::size_t> pending{sc.streams};
        const auto ex = ioc.get_executor();
        for (std::size_t i = 0; i < sc.streams; ++i)
        {
            net::co_spawn(ex, [&, i]() -> net::awaitable<void>
                          {
                auto s = co_await cl.open_stream();
                if (s)
                {
                    bench_options opt;
                    opt.total = sc.per_stream;
                    opt.block = sc.block;
                    reports[i] = co_await bench_throughput_tx(*s, *s, opt);
                    s->close();
                }
                pending.fetch_sub(1, std::memory_order_release); }, net::detached);
        }
        while (pending.load(std::memory_order_acquire) > 0)
        {
            net::steady_timer timer(ex);
            timer.expires_after(std::chrono::milliseconds(10));
            boost::system::error_code sec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, sec));
        }

        double total_bytes = 0;
        double total_sec = 0;
        for (const auto &r : reports)
        {
            total_bytes += static_cast<double>(r.bytes);
            if (r.mbps > 0)
            {
                total_sec += static_cast<double>(r.bytes) / (r.mbps * 1e6 / 8.0);
            }
        }
        // 聚合吞吐 = 总字节 / 并发流的平均耗时
        result.mbps = (total_sec > 0) ? total_bytes * 8.0 / 1e6 / (total_sec / static_cast<double>(sc.streams)) : 0;

        // 延迟：新流单流测量
        auto s2 = co_await cl.open_stream();
        if (s2)
        {
            bench_options opt;
            opt.total = 1000 * 4096;
            opt.block = 4096;
            auto lat = co_await bench_throughput_tx(*s2, *s2, opt);
            result.avg_us = lat.latency_avg * 1000.0;
            result.p50_us = lat.latency_p50 * 1000.0;
            result.p95_us = lat.latency_p95 * 1000.0;
            result.p99_us = lat.latency_p99 * 1000.0;
            s2->close();
        }

        cl.close();
        sv.close();
        result.pass = (total_bytes > 0);
        co_return result;
    }

    /**
     * @brief 打印表头
     */
    void PrintHeader()
    {
        std::cout << "\n====================================================================================\n";
        std::cout << std::format("{:<14}{:>6}{:>8}{:>12}{:>10}{:>10}{:>10}{:>8}\n",
                                 "复用器", "流数", "块", "吞吐", "平均", "p50", "p99", "结果");
        std::cout << "------------------------------------------------------------------------------------\n";
    }

    /**
     * @brief 打印单行
     */
    void PrintRow(const mux_scenario &sc, const mux_result &r)
    {
        std::cout << std::format("{:<14}{:>6}{:>7}K{}{:>11.1f}{}{:>9.1f}{}{:>9.1f}{}{:>9.1f}{}{:>8}\n",
                                 sc.muxer, sc.streams, sc.block / 1024, "",
                                 r.mbps, "", r.avg_us, "", r.p50_us, "", r.p99_us, "",
                                 (r.pass ? "PASS" : "FAIL"));
        if (r.errors > 0)
        {
            std::cout << std::format("  !!! {} 出现 {} 个错误 !!!\n", sc.name, r.errors);
        }
    }

} // namespace

int main(const int argc, char **argv)
{
    (void)argc;
    (void)argv;

#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif

    memory::system::enable_pooling();

    std::cout << "========================================\n";
    std::cout << "  Prism 多路复用端到端压力测试\n";
    std::cout << "  控制变量法: 复用器 × 流数 × 块大小\n";
    std::cout << "  固定: 每流 32MB / 内存管道\n";
    std::cout << "========================================\n";

    std::vector<mux_scenario> scenarios;
    for (const auto &muxer : {"smux", "yamux", "h2mux"})
    {
        for (const auto streams : {1, 8, 32})
        {
            for (const auto block : {65536, 16384})
            {
                scenarios.push_back(mux_scenario{
                    .name = std::string(muxer) + "-" + std::to_string(streams) + "s-" + std::to_string(block / 1024) + "K",
                    .muxer = muxer,
                    .streams = streams,
                    .block = block,
                });
            }
        }
    }

    PrintHeader();

    std::size_t failed = 0;
    for (const auto &sc : scenarios)
    {
        net::io_context ioc;
        mux_result result{};
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            if (sc.muxer == "smux")
            {
                mux::smux::client cl;
                mux::smux::server sv;
                result = co_await run_mux_case(ioc, cl, sv, sc);
            }
            else if (sc.muxer == "yamux")
            {
                mux::yamux::client cl;
                mux::yamux::server sv;
                result = co_await run_mux_case(ioc, cl, sv, sc);
            }
            else
            {
                mux::h2mux::client cl;
                mux::h2mux::server sv;
                result = co_await run_mux_case(ioc, cl, sv, sc);
            }
        };
        net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                      { ep = e; });
        ioc.run_for(std::chrono::seconds(60));

        PrintRow(sc, result);
        if (!result.pass)
        {
            ++failed;
        }
    }

    std::cout << "====================================================================================\n";
    std::cout << std::format("完成: {} 个场景, {} 个失败\n\n", scenarios.size(), failed);
    std::fflush(nullptr);
    std::quick_exit(failed == 0 ? 0 : 1);
}
