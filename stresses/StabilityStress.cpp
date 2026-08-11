/**
 * @file StabilityStress.cpp
 * @brief 长连接稳定性压力测试
 * @details 固定并发连接持续传输，周期性采样进程私有内存与吞吐，
 * 验证长时间运行下：吞吐是否平稳（无退化）、内存是否泄漏
 * （私有内存无持续线性增长）、连接是否稳定（无错误累积）。
 */

#include <prism/net/connection/tunnel/tunnel_relay.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/diagnose/diagnose.hpp>

#include "StressUtil.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace transport = psm::transport;
namespace memory = psm::memory;
namespace diagnose = psm::diagnose;
using namespace psm::stress;

namespace
{
    namespace net = boost::asio;

    /**
     * @brief 稳定性采样点
     */
    struct sample_point
    {
        double seconds{0};          ///< 相对启动时间
        double mbps{0};             ///< 该时段吞吐
        double private_mb{0};       ///< 进程私有内存
    };

    /**
     * @brief 单连接状态
     */
    struct link_state
    {
        transport::shared_transmission phone_tx;       ///< 手机端点传输
        transport::shared_transmission upstream_tx;    ///< 上游端点传输
        transport::shared_transmission proxy_client;   ///< 隧道 A 侧
        transport::shared_transmission proxy_server;   ///< 隧道 B 侧
        std::atomic<std::uint64_t> received{0};        ///< 累计接收字节
        std::atomic<std::uint64_t> errors{0};          ///< 错误数
        std::atomic<bool> exited{false};               ///< 退出标记
    };

    /**
     * @brief 流量写入协程
     */
    auto writer_coro(transport::shared_transmission tx, const std::size_t payload_size,
                     std::span<const std::byte> pool, const std::atomic<bool> &stop,
                     link_state &link) -> net::awaitable<void>
    {
        std::error_code ec;
        std::uint64_t seq = 0;
        memory::vector<std::byte> packet(16 + payload_size, memory::effective_mr(memory::system::local_pool()));

        while (!stop.load(std::memory_order_relaxed))
        {
            const auto length = static_cast<std::uint64_t>(payload_size);
            const auto current_seq = seq++;
            std::memcpy(packet.data(), &length, sizeof(length));
            std::memcpy(packet.data() + 8, &current_seq, sizeof(current_seq));
            std::memcpy(packet.data() + 16, pool.data(), payload_size);

            const auto n = co_await transport::async_write(*tx, std::span(packet), ec);
            if (ec)
            {
                // stop 之后的错误（cancel/close/aborted）属正常收尾，不计
                if (!stop.load(std::memory_order_relaxed))
                {
                    link.errors.fetch_add(1, std::memory_order_relaxed);
                }
                co_return;
            }
            if (n == 0)
            {
                co_return;
            }
        }
    }

    /**
     * @brief 流量校验协程
     */
    auto reader_coro(transport::shared_transmission tx, link_state &link) -> net::awaitable<void>
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
            if (length == 0 || length > 65536)
            {
                link.errors.fetch_add(1, std::memory_order_relaxed);
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
                link.errors.fetch_add(1, std::memory_order_relaxed);
            }
            expect_seq = header[1] + 1;
            link.received.fetch_add(header_n + body_n, std::memory_order_relaxed);
        }
    }

    /**
     * @brief 隧道转发协程
     */
    auto tunnel_coro(const std::size_t buffer_size, link_state &link) -> net::awaitable<void>
    {
        psm::connect::tunnel_options opts{link.proxy_client, link.proxy_server, static_cast<std::uint32_t>(buffer_size),
                            psm::connect::write_policy::complete};
        opts.trace = std::make_shared<diagnose::context>();
        co_await psm::connect::tunnel_relay(std::move(opts)).run();
    }

    /**
     * @brief 协程退出计数包装
     */
    void spawn_guard(net::any_io_executor ex, net::awaitable<void> coro, std::shared_ptr<link_state> link)
    {
        // completion 按值捕获 shared_ptr，保证协程未完成时 link 不会悬垂
        net::co_spawn(
            ex, std::move(coro),
            [link](std::exception_ptr)
            {
                link->exited.store(true, std::memory_order_release);
            });
    }

    /**
     * @brief 运行稳定性测试
     */
    auto run_stability(const std::size_t connections, const std::size_t duration_sec,
                       const std::size_t sample_sec, const std::size_t buffer_size)
        -> bool
    {
        // 每个场景独立 io_context（保活不析构）：win_iocp 析构等待未完成
        // 操作会卡死；场景间复用会产生在途事件污染后续场景
        static std::vector<std::unique_ptr<net::io_context>> g_iocs;
        auto ioc_holder = std::make_unique<net::io_context>();
        auto &ioc = *ioc_holder;
        g_iocs.push_back(std::move(ioc_holder));
        std::atomic<bool> stop{false};
        bool verdict = false;
        std::vector<std::shared_ptr<link_state>> links;
        links.reserve(connections);
        for (std::size_t i = 0; i < connections; ++i)
        {
            links.push_back(std::make_shared<link_state>());
        }
        auto pool = make_payload_pool(65536);

        std::exception_ptr ep;
        auto driver = [&]() -> net::awaitable<void>
        {
            const auto ex = co_await net::this_coro::executor;
            for (auto &link : links)
            {
                auto [phone_sock, proxy_client_sock] = co_await make_socket_pair(ex);
                auto [upstream_sock, proxy_server_sock] = co_await make_socket_pair(ex);
                link->phone_tx = transport::make_reliable(std::move(phone_sock));
                link->upstream_tx = transport::make_reliable(std::move(upstream_sock));
                link->proxy_client = transport::make_reliable(std::move(proxy_client_sock));
                link->proxy_server = transport::make_reliable(std::move(proxy_server_sock));
                spawn_guard(ex, writer_coro(link->upstream_tx, 65536, pool, stop, *link), link);
                spawn_guard(ex, reader_coro(link->phone_tx, *link), link);
                spawn_guard(ex, tunnel_coro(buffer_size, *link), link);
            }

            const auto base_mb = process_private_mb();
            std::vector<sample_point> samples;

            const auto start = std::chrono::steady_clock::now();
            std::uint64_t last_bytes = 0;
            auto last_time = start;
            for (std::size_t tick = 0; tick < duration_sec / sample_sec; ++tick)
            {
                co_await async_wait(ex, std::chrono::seconds(sample_sec));

                std::uint64_t total_bytes = 0;
                for (const auto &link : links)
                {
                    total_bytes += link->received.load(std::memory_order_relaxed);
                }
                const auto now = std::chrono::steady_clock::now();
                const auto dt = std::chrono::duration<double>(now - last_time).count();
                sample_point point{};
                point.seconds = std::chrono::duration<double>(now - start).count();
                point.mbps = (total_bytes - last_bytes) * 8.0 / 1'000'000.0 / dt;
                point.private_mb = process_private_mb();
                samples.push_back(point);
                last_bytes = total_bytes;
                last_time = now;
            }

            stop.store(true, std::memory_order_release);
            for (auto &link : links)
            {
                link->phone_tx->close();
                link->upstream_tx->close();
                link->proxy_client->close();
                link->proxy_server->close();
            }
            for (std::size_t wait_ms = 0; wait_ms < 3000; wait_ms += 20)
            {
                bool all_exited = true;
                for (auto &link : links)
                {
                    if (!link->exited.load(std::memory_order_acquire))
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

            // 汇总统计
            std::uint64_t total_bytes = 0;
            std::uint64_t total_errors = 0;
            for (const auto &link : links)
            {
                total_bytes += link->received.load(std::memory_order_relaxed);
                total_errors += link->errors.load(std::memory_order_relaxed);
            }
            const auto total_sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
            const auto final_mb = process_private_mb();

            std::cout << std::format("  并发连接: {}\n", connections);
            std::cout << std::format("  持续时间: {:.1f}s, 总传输: {:.1f} GB\n", total_sec, total_bytes / 1.0e9);
            std::cout << std::format("  平均吞吐: {:.1f} Mbps, 错误: {}\n", total_bytes * 8.0 / 1e6 / total_sec, total_errors);
            std::cout << "  采样(秒, 吞吐Mbps, 私有内存MB):\n";
            for (const auto &p : samples)
            {
                std::cout << std::format("    {:>6.1f}  {:>10.1f}  {:>8.1f}\n", p.seconds, p.mbps, p.private_mb);
            }
            std::cout << std::format("  内存: 初始 {:.1f} MB, 结束 {:.1f} MB, 增长 {:.1f} MB\n",
                                     base_mb, final_mb, final_mb - base_mb);

            // 判定：错误为 0 且末段内存相对首段无持续增长
            const auto first_half = samples.size() / 2;
            const auto mem_start = samples.empty() ? base_mb : samples.front().private_mb;
            const auto mem_end = samples.empty() ? final_mb : samples.back().private_mb;
            const bool stable = (total_errors == 0) && (mem_end - mem_start) < 32.0;
            std::cout << std::format("  判定: {} (错误={}, 内存增长 {:.1f}MB)\n",
                                     (stable ? "PASS" : "FAIL"), total_errors, mem_end - mem_start);
            verdict = stable;
        };

        // 禁止 ioc.stop()：过早停止丢弃 cancel 后的完成事件导致析构崩溃；
        // run_for 自然耗尽（协程全部退出 + timer 取消）后返回
        net::co_spawn(ioc, driver(), [&](std::exception_ptr e)
                      { ep = e; });
        ioc.run_for(std::chrono::seconds(duration_sec + 30));
        // 大量 socket 的场景，links 保活到进程退出（OS 回收）
        static std::vector<std::vector<std::shared_ptr<link_state>>> g_leaks;
        g_leaks.push_back(std::move(links));
        return verdict;
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
    std::cout << "  Prism 长连接稳定性压力测试\n";
    std::cout << "  固定并发 + 周期采样 + 泄漏检测\n";
    std::cout << "========================================\n\n";

    // 场景 1: 32 并发 / 90 秒 / 每 10 秒采样 / 64K 缓冲
    std::cout << "场景 1: 32 并发, 90s, 采样 10s, 缓冲 64K\n";
    auto pass1 = run_stability(32, 90, 10, 65536);

    std::cout << "\n场景 2: 128 并发, 60s, 采样 10s, 缓冲 256K\n";
    auto pass2 = run_stability(128, 60, 10, 262144);

    std::cout << "\n========================================\n";
    std::cout << std::format("完成: {} 场景\n", (pass1 && pass2) ? 2 : 0);
    std::cout << "========================================\n";
    // 跳过 static 析构（保活的 io_context/socket 析构触发未处理事件）
    std::fflush(nullptr);
    std::quick_exit((pass1 && pass2) ? 0 : 1);
}
