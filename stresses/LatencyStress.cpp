/**
 * @file LatencyStress.cpp
 * @brief 高并发高负载下延迟压力测试
 * @details 控制变量法：变量 = 并发连接数 × 负载强度 × 缓冲大小。
 * 每个连接在持续大流量（满载带宽）的同时，周期性注入 32B 探针包
 * 经隧道环回，测量高负载下的往返延迟分布（p50/p95/p99/p999），
 * 验证高并发高负载下延迟是否劣化（排队延迟/调度抖动）。
 */

#include <prism/net/connection/tunnel/tunnel_relay.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/diagnose/diagnose.hpp>

#include "StressUtil.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

using namespace psm;

namespace transport = psm::transport;
namespace memory = psm::memory;
namespace diagnose = psm::diagnose;
using namespace psm::stress;

namespace
{
    namespace net = boost::asio;

    // 探针标记：length 字段的特殊值（普通报文 length 最大 131072）
    constexpr std::uint64_t kProbeMark = 0xFFFFFFFFFFFFFFFFULL;
    // 普通报文 payload 大小
    constexpr std::size_t kPayloadSize = 65536;

    /**
     * @brief 场景定义
     */
    struct lat_scenario
    {
        std::string name;                ///< 场景名称
        std::size_t connections{16};     ///< 并发连接数
        std::size_t buffer{65536};       ///< 隧道缓冲
        bool half_load{false};           ///< 半载（流量占空比 50%）
        std::size_t duration_ms{5000};   ///< 持续时间
        std::size_t probe_interval_ms{50}; ///< 探针间隔
    };

    /**
     * @brief 单连接统计
     */
    struct link_stats
    {
        std::atomic<std::uint64_t> received{0};
        std::atomic<std::uint64_t> errors{0};
        std::atomic<bool> exited{false};
        // 延迟样本（协程内收集，场景结束时汇总）
        std::vector<std::uint64_t> rtt_us;
    };

    /**
     * @brief 场景结果
     */
    struct lat_result
    {
        std::uint64_t total_bytes{0};
        std::uint64_t errors{0};
        std::size_t probes{0};
        double seconds{0};
        double mbps{0};
        double p50_us{0};
        double p95_us{0};
        double p99_us{0};
        double p999_us{0};
        double max_us{0};
        bool pass{false};
    };

    /**
     * @brief 单连接三段结构
     */
    struct harness
    {
        transport::shared_transmission phone_tx;
        transport::shared_transmission upstream_tx;
        transport::shared_transmission proxy_client;
        transport::shared_transmission proxy_server;
        link_stats stats;
    };

    /**
     * @brief 上游写入协程：持续大流量 + 周期性探针
     */
    auto writer_coro(transport::shared_transmission tx, const lat_scenario &sc,
                     std::span<const std::byte> pool, const std::atomic<bool> &stop,
                     harness &h) -> net::awaitable<void>
    {
        std::error_code ec;
        std::uint64_t seq = 0;
        memory::vector<std::byte> big(16 + kPayloadSize, memory::effective_mr(memory::system::local_pool()));
        memory::vector<std::byte> probe(32, memory::effective_mr(memory::system::local_pool()));

        auto next_probe = std::chrono::steady_clock::now();
        const auto burst_interval = std::chrono::milliseconds(90);
        // 初始化为过去时间，确保首轮进入突发窗口
        auto burst_until = std::chrono::steady_clock::now() - burst_interval;

        while (!stop.load(std::memory_order_relaxed))
        {
            const auto now = std::chrono::steady_clock::now();

            // 半载模式：16 个大包 + 2 个探针突发，随后 60ms 空闲（约 50% 占空比）
            if (sc.half_load)
            {
                for (int b = 0; b < 16; ++b)
                {
                    if (b == 0 || b == 8)
                    {
                        const auto length = kProbeMark;
                        const auto ts = static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count());
                        std::memcpy(probe.data(), &length, 8);
                        std::memcpy(probe.data() + 8, &ts, 8);
                        const auto pn = co_await transport::async_write(*tx, std::span(probe).first(16), ec);
                        if (ec)
                        {
                            co_return;
                        }
                        (void)pn;
                    }
                    const auto length = static_cast<std::uint64_t>(kPayloadSize);
                    const auto current_seq = seq++;
                    std::memcpy(big.data(), &length, 8);
                    std::memcpy(big.data() + 8, &current_seq, 8);
                    std::memcpy(big.data() + 16, pool.data(), kPayloadSize);
                    const auto bn = co_await transport::async_write(*tx, std::span(big), ec);
                    if (ec)
                    {
                        co_return;
                    }
                    (void)bn;
                }
                co_await async_wait(co_await net::this_coro::executor, std::chrono::milliseconds(60));
                continue;
            }

            // 满载模式
            if (now >= next_probe)
            {
                const auto length = kProbeMark;
                const auto ts = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        now.time_since_epoch()).count());
                std::memcpy(probe.data(), &length, 8);
                std::memcpy(probe.data() + 8, &ts, 8);
                // 探针固定 16B（header 即完整报文），避免流边界错位
                const auto n = co_await transport::async_write(*tx, std::span(probe).first(16), ec);
                if (ec)
                {
                    if (!stop.load(std::memory_order_relaxed))
                    {
                        h.stats.errors.fetch_add(1, std::memory_order_relaxed);
                    }
                    co_return;
                }
                next_probe = now + std::chrono::milliseconds(sc.probe_interval_ms);
            }
            const auto length = static_cast<std::uint64_t>(kPayloadSize);
            const auto current_seq = seq++;
            std::memcpy(big.data(), &length, 8);
            std::memcpy(big.data() + 8, &current_seq, 8);
            std::memcpy(big.data() + 16, pool.data(), kPayloadSize);
            const auto n = co_await transport::async_write(*tx, std::span(big), ec);
            if (ec)
            {
                if (!stop.load(std::memory_order_relaxed))
                {
                    h.stats.errors.fetch_add(1, std::memory_order_relaxed);
                }
                co_return;
            }
            (void)n;
        }
    }

    /**
     * @brief 手机端消费协程：大包丢弃校验 + 探针回显
     */
    auto reader_coro(transport::shared_transmission tx, harness &h) -> net::awaitable<void>
    {
        std::error_code ec;
        std::uint64_t expect_seq = 0;
        std::array<std::uint64_t, 2> header{};
        memory::vector<std::byte> discard(16, memory::effective_mr(memory::system::local_pool()));

        while (true)
        {
            const auto header_n = co_await transport::async_read(
                *tx, std::span(reinterpret_cast<std::byte *>(header.data()), sizeof(header)), ec);
            if (ec || header_n == 0)
            {
                co_return;
            }
            const auto length = header[0];
            if (length == kProbeMark)
            {
                // 探针：立即回显（echo 反向经隧道），16B 完整回传
                std::array<std::uint64_t, 2> echo{};
                echo[0] = kProbeMark;
                echo[1] = header[1];
                const auto wn = co_await transport::async_write(
                    *tx, std::span(reinterpret_cast<std::byte *>(echo.data()), sizeof(echo)), ec);
                if (ec || wn == 0)
                {
                    co_return;
                }
                continue;
            }
            if (length == 0 || length > 131072)
            {
                h.stats.errors.fetch_add(1, std::memory_order_relaxed);
                co_return;
            }
            if (discard.size() < length)
            {
                discard.resize(length);
            }
            const auto body_n = co_await transport::async_read(*tx, std::span(discard).first(length), ec);
            if (ec || body_n == 0)
            {
                co_return;
            }
            if (header[1] != expect_seq)
            {
                h.stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
            expect_seq = header[1] + 1;
            h.stats.received.fetch_add(header_n + body_n, std::memory_order_relaxed);
        }
    }

    /**
     * @brief 回显接收协程：接收探针回声并计算 RTT
     */
    auto echo_coro(transport::shared_transmission tx, harness &h, const std::atomic<bool> &stop)
        -> net::awaitable<void>
    {
        std::error_code ec;
        std::array<std::uint64_t, 4> echo{};
        while (!stop.load(std::memory_order_relaxed))
        {
            const auto n = co_await transport::async_read(
                *tx, std::span(reinterpret_cast<std::byte *>(echo.data()), sizeof(echo)), ec);
            if (ec || n == 0)
            {
                co_return;
            }
            if (echo[0] == kProbeMark)
            {
                const auto now = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                const auto rtt = static_cast<std::uint64_t>(now - static_cast<std::int64_t>(echo[1]));
                h.stats.rtt_us.push_back(rtt);
            }
        }
    }

    /**
     * @brief 隧道转发协程
     */
    auto tunnel_coro(const lat_scenario &sc, harness &h) -> net::awaitable<void>
    {
        psm::connect::tunnel_options opts{h.proxy_client, h.proxy_server, static_cast<std::uint32_t>(sc.buffer),
                                          psm::connect::write_policy::complete};
        opts.trace = std::make_shared<diagnose::context>();
        co_await psm::connect::tunnel_relay(std::move(opts)).run();
    }

    /**
     * @brief 协程退出计数包装
     */
    auto spawn_guard(net::any_io_executor ex, net::awaitable<void> coro, std::shared_ptr<harness> h)
    {
        net::co_spawn(
            ex, std::move(coro),
            [h](std::exception_ptr)
            {
                h->stats.exited.store(true, std::memory_order_release);
            });
    }

    /**
     * @brief 分位数计算
     */
    [[nodiscard]] auto percentile(std::vector<std::uint64_t> &samples, const double p) -> double
    {
        if (samples.empty())
        {
            return 0.0;
        }
        const auto idx = static_cast<std::size_t>(static_cast<double>(samples.size()) * p);
        const auto pos = (std::max)(std::size_t{0}, (std::min)(idx, samples.size() - 1));
        return static_cast<double>(samples[pos]);
    }

    /**
     * @brief 运行单个场景
     */
    auto run_scenario(const lat_scenario &sc) -> lat_result
    {
        static std::vector<std::unique_ptr<net::io_context>> g_iocs;
        auto ioc_holder = std::make_unique<net::io_context>();
        auto &ioc = *ioc_holder;
        g_iocs.push_back(std::move(ioc_holder));
        std::atomic<bool> stop{false};
        std::vector<std::shared_ptr<harness>> harnesses;
        harnesses.reserve(sc.connections);
        for (std::size_t i = 0; i < sc.connections; ++i)
        {
            harnesses.push_back(std::make_shared<harness>());
        }
        auto pool = make_payload_pool(65536);

        std::exception_ptr ep;
        auto driver = [&]() -> net::awaitable<void>
        {
            const auto ex = co_await net::this_coro::executor;
            for (auto &h : harnesses)
            {
                auto [phone_sock, proxy_client_sock] = co_await make_socket_pair(ex);
                auto [upstream_sock, proxy_server_sock] = co_await make_socket_pair(ex);
                h->phone_tx = transport::make_reliable(std::move(phone_sock));
                h->upstream_tx = transport::make_reliable(std::move(upstream_sock));
                h->proxy_client = transport::make_reliable(std::move(proxy_client_sock));
                h->proxy_server = transport::make_reliable(std::move(proxy_server_sock));

                spawn_guard(ex, writer_coro(h->upstream_tx, sc, pool, stop, *h), h);
                spawn_guard(ex, reader_coro(h->phone_tx, *h), h);
                spawn_guard(ex, echo_coro(h->upstream_tx, *h, stop), h);
                spawn_guard(ex, tunnel_coro(sc, *h), h);
            }

            co_await async_wait(ex, std::chrono::milliseconds(sc.duration_ms));
            stop.store(true, std::memory_order_release);

            for (auto &h : harnesses)
            {
                h->phone_tx->close();
                h->upstream_tx->close();
                h->proxy_client->close();
                h->proxy_server->close();
            }

            for (std::size_t wait_ms = 0; wait_ms < 30000; wait_ms += 20)
            {
                bool all_exited = true;
                for (auto &h : harnesses)
                {
                    if (!h->stats.exited.load(std::memory_order_acquire))
                    {
                        all_exited = false;
                        break;
                    }
                }
                if (all_exited)
                {
                    break;
                }
                co_await async_wait(ex, std::chrono::milliseconds(20));
            }
        };

        const auto wall_start = std::chrono::steady_clock::now();
        net::co_spawn(ioc, driver(), [&](std::exception_ptr e)
                      { ep = e; });
        ioc.run_for(std::chrono::milliseconds(sc.duration_ms + 30000));
        const auto wall_end = std::chrono::steady_clock::now();

        lat_result result{};
        result.seconds = std::chrono::duration<double>(wall_end - wall_start).count();
        std::vector<std::uint64_t> all_rtt;
        for (const auto &h : harnesses)
        {
            result.total_bytes += h->stats.received.load(std::memory_order_relaxed);
            result.errors += h->stats.errors.load(std::memory_order_relaxed);
            all_rtt.insert(all_rtt.end(), h->stats.rtt_us.begin(), h->stats.rtt_us.end());
        }
        std::sort(all_rtt.begin(), all_rtt.end());
        result.probes = all_rtt.size();
        result.mbps = result.total_bytes * 8.0 / 1'000'000.0 / result.seconds;
        result.p50_us = percentile(all_rtt, 0.50);
        result.p95_us = percentile(all_rtt, 0.95);
        result.p99_us = percentile(all_rtt, 0.99);
        result.p999_us = percentile(all_rtt, 0.999);
        result.max_us = all_rtt.empty() ? 0.0 : static_cast<double>(all_rtt.back());
        result.pass = (result.errors == 0 && result.probes > 0);

        static std::vector<std::vector<std::shared_ptr<harness>>> g_leaks;
        g_leaks.push_back(std::move(harnesses));
        return result;
    }

    /**
     * @brief 打印表头
     */
    void PrintHeader()
    {
        std::cout << "\n====================================================================================\n";
        std::cout << std::format("{:<14}{:>6}{:>6}{:>11}{:>10}{:>10}{:>10}{:>10}{:>10}{:>8}\n",
                                 "场景", "并发", "负载", "吞吐", "p50", "p95", "p99", "p999", "max", "结果");
        std::cout << "------------------------------------------------------------------------------------\n";
    }

    /**
     * @brief 打印单行
     */
    void PrintRow(const lat_scenario &sc, const lat_result &r)
    {
        std::cout << std::format("{:<14}{:>6}{:>6}{:>10.0f}M{}{:>9.1f}{}{:>9.1f}{}{:>9.1f}{}{:>9.1f}{}{:>9.1f}{}{:>8}\n",
                                 sc.name, sc.connections, (sc.half_load ? "半载" : "满载"),
                                 r.mbps, "", r.p50_us, "", r.p95_us, "", r.p99_us, "",
                                 r.p999_us, "", r.max_us, "",
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
    std::cout << "  Prism 高并发高负载延迟压力测试\n";
    std::cout << "  大流量背景下探针 RTT (p50/p95/p99/p999)\n";
    std::cout << "========================================\n";

    const std::vector<lat_scenario> scenarios = {
        lat_scenario{.name = "L1 并发16满载"},
        lat_scenario{.name = "L2 并发64满载", .connections = 64},
        lat_scenario{.name = "L3 并发256满载", .connections = 256},
        lat_scenario{.name = "L4 并发64半载", .connections = 64, .half_load = true},
        lat_scenario{.name = "L5 并发64·256K", .connections = 64, .buffer = 262144},
        lat_scenario{.name = "L6 并发512满载", .connections = 512},
    };

    PrintHeader();

    std::size_t failed = 0;
    for (const auto &sc : scenarios)
    {
        const auto result = run_scenario(sc);
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
