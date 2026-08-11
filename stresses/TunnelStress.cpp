/**
 * @file TunnelStress.cpp
 * @brief 端到端隧道转发压力测试
 * @details 使用真实 TCP socket 对 + tunnel_relay 双向转发，
 * 通过控制变量法（单变量变化、其余固定基线）模拟不同生产环境：
 * 并发连接数、缓冲区大小、链路 RTT、报文大小分布、突发流量模式。
 * 每个场景输出聚合吞吐、单连接吞吐与错误数。
 *
 * 架构（与真实代理一致，避免单 socket 双读冲突）：
 *   手机端点 ──A── 代理隧道(tunnel_relay) ──B── 上游端点
 *   上游端点持续写入数据，隧道双向转发，手机端点接收校验。
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
#include <thread>
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

    /**
     * @brief 场景定义（控制变量法的单变量描述）
     */
    struct tunnel_scenario
    {
        std::string name;                       ///< 场景名称
        std::size_t connections{16};            ///< 并发连接数
        std::size_t buffer_size{65536};         ///< 隧道转发缓冲区大小
        std::chrono::microseconds rtt{0};       ///< 模拟链路 RTT
        std::size_t payload_min{65536};         ///< 报文最小 payload
        std::size_t payload_max{65536};         ///< 报文最大 payload
        bool burst{false};                      ///< 突发流量模式
        std::size_t duration_ms{3000};          ///< 场景持续时间
    };

    /**
     * @brief 单连接统计
     */
    struct conn_stats
    {
        std::atomic<std::uint64_t> received{0}; ///< 接收字节数
        std::atomic<std::uint64_t> packets{0};  ///< 接收报文数
        std::atomic<std::uint64_t> errors{0};   ///< 错误数
    };

    /**
     * @brief 场景结果
     */
    struct scenario_result
    {
        std::uint64_t total_bytes{0};           ///< 总接收字节
        std::uint64_t errors{0};                ///< 总错误数
        double seconds{0};                      ///< 实际耗时
        double mbps{0};                         ///< 聚合吞吐
        double per_conn_mbps{0};                ///< 单连接吞吐
        bool pass{false};                       ///< 是否通过
    };

    /**
     * @brief 单连接三段结构（手机端点 / 隧道 / 上游端点）
     */
    struct harness
    {
        transport::shared_transmission phone_tx;      ///< 手机端点传输（A 端）
        transport::shared_transmission upstream_tx;   ///< 上游端点传输（B 端）
        transport::shared_transmission proxy_client;  ///< 隧道 A 侧
        transport::shared_transmission proxy_server;  ///< 隧道 B 侧（可能含 RTT 延迟）
        conn_stats stats;                              ///< 连接统计
        std::atomic<bool> exited{false};               ///< 协程组退出标记
    };

    /**
     * @brief 生成报文大小（固定或随机区间）
     */
    [[nodiscard]] auto pick_payload_size(const tunnel_scenario &sc, std::mt19937 &rng) -> std::size_t
    {
        if (sc.payload_min == sc.payload_max)
        {
            return sc.payload_min;
        }
        std::uniform_int_distribution<std::size_t> dist(sc.payload_min, sc.payload_max);
        return dist(rng);
    }

    /**
     * @brief 上游流量写入协程：持续生成「长度头 + 序号 + payload」报文
     */
    auto writer_coro(transport::shared_transmission tx, const tunnel_scenario &sc,
                     std::span<const std::byte> pool, const std::atomic<bool> &stop,
                     harness &h) -> net::awaitable<void>
    {
        std::mt19937 rng(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&h)));
        std::error_code ec;
        std::uint64_t seq = 0;
        memory::vector<std::byte> packet(16 + sc.payload_max, memory::effective_mr(memory::system::local_pool()));

        auto burst_until = std::chrono::steady_clock::now();

        while (!stop.load(std::memory_order_relaxed))
        {
            const auto payload_size = pick_payload_size(sc, rng);
            const auto length = static_cast<std::uint64_t>(payload_size);
            const auto current_seq = seq++;
            std::memcpy(packet.data(), &length, sizeof(length));
            std::memcpy(packet.data() + 8, &current_seq, sizeof(current_seq));
            std::memcpy(packet.data() + 16, pool.data(), payload_size);

            const auto n = co_await transport::async_write(*tx, std::span(packet).first(16 + payload_size), ec);
            if (ec)
            {
                // stop 之后的错误（cancel/close/aborted）属正常收尾，不计
                if (!stop.load(std::memory_order_relaxed))
                {
                    h.stats.errors.fetch_add(1, std::memory_order_relaxed);
                }
                co_return;
            }
            if (n == 0)
            {
                co_return;
            }

            if (sc.burst)
            {
                const auto now = std::chrono::steady_clock::now();
                if (now < burst_until)
                {
                    continue;
                }
                burst_until = now + std::chrono::milliseconds(90);
                co_await async_wait(co_await net::this_coro::executor, std::chrono::milliseconds(90));
            }
        }
    }

    /**
     * @brief 手机端校验协程：读取「长度头 + 序号 + payload」并校验连续性
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
            const auto current_seq = header[1];
            if (length == 0 || length > 65536)
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

            if (current_seq != expect_seq)
            {
                h.stats.errors.fetch_add(1, std::memory_order_relaxed);
            }
            expect_seq = current_seq + 1;
            h.stats.received.fetch_add(header_n + body_n, std::memory_order_relaxed);
            h.stats.packets.fetch_add(1, std::memory_order_relaxed);
        }
    }

    /**
     * @brief 隧道转发协程
     */
    auto tunnel_coro(const tunnel_scenario &sc, harness &h) -> net::awaitable<void>
    {
        psm::connect::tunnel_options opts{h.proxy_client, h.proxy_server, static_cast<std::uint32_t>(sc.buffer_size),
                                          psm::connect::write_policy::complete};
        opts.trace = std::make_shared<diagnose::context>();
        co_await psm::connect::tunnel_relay(std::move(opts)).run();
    }

    /**
     * @brief 协程组包装：计数退出
     */
    auto spawn_guard(net::any_io_executor ex, net::awaitable<void> coro, std::shared_ptr<harness> h)
    {
        // completion 按值捕获 shared_ptr，保证协程未完成时 harness 不会悬垂
        net::co_spawn(
            ex, std::move(coro),
            [h](std::exception_ptr)
            {
                h->exited.store(true, std::memory_order_release);
            });
    }

    /**
     * @brief 运行单个场景
     * @note io_context 全局常驻（与生产环境 worker ioc 生命周期一致），
     * 场景间复用避免反复创建/销毁；进程退出时由 OS 回收，
     * 不析构 io_context（win_iocp 析构会等待未完成操作导致卡死）。
     */
    auto run_scenario(const tunnel_scenario &sc) -> scenario_result
    {
        // 每个场景独立 io_context（保活不析构，进程退出由 OS 回收）：
        // 1) win_iocp 析构会等待未完成操作导致卡死；2) 场景间复用会产生
        // 在途完成事件污染下一个场景的 connect/accept。
        static std::vector<std::unique_ptr<net::io_context>> g_iocs;
        auto ioc_holder = std::make_unique<net::io_context>();
        auto &ioc = *ioc_holder;
        g_iocs.push_back(std::move(ioc_holder));
        // PMR local_pool 线程封闭：单线程驱动 io_context，协程不跨线程迁移
        std::atomic<bool> stop{false};
        std::vector<std::shared_ptr<harness>> harnesses;
        harnesses.reserve(sc.connections);

        for (std::size_t i = 0; i < sc.connections; ++i)
        {
            harnesses.push_back(std::make_shared<harness>());
        }

        // 随机 payload 池
        auto pool = make_payload_pool(sc.payload_max > 4096 ? sc.payload_max : 4096);

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
                if (sc.rtt.count() > 0)
                {
                    // 延迟包装在 mirror 的写方向（代理→手机链路），
                    // 数据每块经写延迟 RTT/2，模拟完整往返 RTT
                    h->proxy_client = std::make_shared<delayed_transport>(h->proxy_client, sc.rtt / 2);
                }

                spawn_guard(ex, writer_coro(h->upstream_tx, sc, pool, stop, *h), h);
                spawn_guard(ex, reader_coro(h->phone_tx, *h), h);
                spawn_guard(ex, tunnel_coro(sc, *h), h);
            }

            co_await async_wait(ex, std::chrono::milliseconds(sc.duration_ms));
            stop.store(true, std::memory_order_release);

            // 关闭全部传输，驱动协程退出
            for (auto &h : harnesses)
            {
                h->phone_tx->close();
                h->upstream_tx->close();
                h->proxy_client->close();
                h->proxy_server->close();
            }

            // 等待协程组全部退出（每 20ms 轮询，最多 30 秒）
            for (std::size_t wait_ms = 0; wait_ms < 30000; wait_ms += 20)
            {
                bool all_exited = true;
                for (auto &h : harnesses)
                {
                    if (!h->exited.load(std::memory_order_acquire))
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
        // 注意：禁止 ioc.stop() —— 过早停止会丢弃 cancel 后的 I/O 完成事件，
        // 导致 socket 携带未完成操作析构（访问冲突）。协程全部退出后
        // io_context 无挂起工作，run_for 自然返回。
        net::co_spawn(ioc, driver(), [&](std::exception_ptr e)
                      {
                          if (e)
                          {
                              try { std::rethrow_exception(e); }
                              catch (const std::exception &ex) { std::cerr << "[driver-ex: " << ex.what() << "]" << std::flush; }
                          }
                          ep = e;
                      });
        const auto rf_start = std::chrono::steady_clock::now();
        ioc.run_for(std::chrono::milliseconds(sc.duration_ms + 30000));
        const auto rf_elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - rf_start).count();
        const auto wall_end = std::chrono::steady_clock::now();

        scenario_result result{};
        result.seconds = std::chrono::duration<double>(wall_end - wall_start).count();
        for (const auto &h : harnesses)
        {
            result.total_bytes += h->stats.received.load(std::memory_order_relaxed);
            result.errors += h->stats.errors.load(std::memory_order_relaxed);
        }
        result.mbps = result.total_bytes * 8.0 / 1'000'000.0 / result.seconds;
        result.per_conn_mbps = result.mbps / static_cast<double>(sc.connections);
        result.pass = (result.errors == 0 && result.total_bytes > 0);
        // 大量 socket 的场景，harness 保活到进程退出（OS 回收），
        // 避免关闭风暴触发的未处理完成事件导致析构崩溃
        static std::vector<std::vector<std::shared_ptr<harness>>> g_leaks;
        g_leaks.push_back(std::move(harnesses));
        return result;
    }

    /**
     * @brief 打印场景表头
     */
    void PrintHeader()
    {
        std::cout << "\n==================================================================================================\n";
        std::cout << std::format("{:<12}{:>6}{:>8}{:>8}{:>12}{:>12}{:>14}{:>8}\n",
                                 "场景", "并发", "缓冲", "RTT", "报文", "吞吐", "单连接", "结果");
        std::cout << "--------------------------------------------------------------------------------------------------\n";
    }

    /**
     * @brief 打印单行场景结果
     */
    void PrintRow(const tunnel_scenario &sc, const scenario_result &r)
    {
        std::string rtt = (sc.rtt.count() == 0) ? "0ms" : std::format("{}ms", sc.rtt.count() / 1000);
        std::string payload = (sc.payload_min == sc.payload_max)
                                  ? std::format("{}B", sc.payload_min)
                                  : std::format("{}-{}B", sc.payload_min, sc.payload_max);
        std::string buf = std::format("{}K", sc.buffer_size / 1024);
        std::cout << std::format("{:<12}{:>6}{:>8}{:>8}{:>12}{:>9.1f}M{}{:>9.1f}M{}{:>8}\n",
                                 sc.name, sc.connections, buf, rtt, payload,
                                 r.mbps, "", r.per_conn_mbps, "",
                                 (r.pass ? "PASS" : "FAIL"));
        if (r.errors > 0)
        {
            std::cout << std::format("  !!! 场景 {} 出现 {} 个错误 !!!\n", sc.name, r.errors);
        }
    }

    /**
     * @brief 构建场景矩阵（基线 = 并发 16 / 缓冲 64K / RTT 0 / 报文 64K）
     */
    auto build_scenarios() -> std::vector<tunnel_scenario>
    {
        std::vector<tunnel_scenario> list;

        list.push_back(tunnel_scenario{.name = "S1 单连接", .connections = 1});
        list.push_back(tunnel_scenario{.name = "S2 并发16", .connections = 16});
        list.push_back(tunnel_scenario{.name = "S3 并发64", .connections = 64});
        list.push_back(tunnel_scenario{.name = "S4 并发256", .connections = 256});
        list.push_back(tunnel_scenario{.name = "S5 缓冲16K", .buffer_size = 16384});
        list.push_back(tunnel_scenario{.name = "S6 缓冲256K", .buffer_size = 262144});
        list.push_back(tunnel_scenario{.name = "S7 局域网1ms", .rtt = std::chrono::microseconds(1000)});
        list.push_back(tunnel_scenario{.name = "S8 跨城20ms", .rtt = std::chrono::microseconds(20000)});
        list.push_back(tunnel_scenario{.name = "S9 跨洋100ms", .rtt = std::chrono::microseconds(100000)});
        list.push_back(tunnel_scenario{.name = "S10 小报文64B", .payload_min = 64, .payload_max = 64});
        list.push_back(tunnel_scenario{.name = "S11 混合报文", .payload_min = 64, .payload_max = 65536});
        list.push_back(tunnel_scenario{.name = "S12 突发流量", .burst = true});
        return list;
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
    std::cout << "  Prism 端到端隧道转发压力测试\n";
    std::cout << "  控制变量法: 每个场景仅改变一个变量\n";
    std::cout << "  基线: 并发16 / 缓冲64K / RTT 0 / 报文64K\n";
    std::cout << "========================================\n";

    const auto scenarios = build_scenarios();
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

    std::cout << "==================================================================================================\n";
    std::cout << std::format("完成: {} 个场景, {} 个失败\n\n", scenarios.size(), failed);
    // 跳过全局/静态析构：常驻 io_context 的 win_iocp 析构会等待未完成操作，
    // 保活的 socket 在 static 析构阶段关闭也会触发未处理完成事件
    std::fflush(nullptr);
    std::quick_exit(failed == 0 ? 0 : 1);
}
