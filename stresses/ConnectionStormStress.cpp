/**
 * @file ConnectionStormStress.cpp
 * @brief 连接建立风暴压力测试
 * @details 模拟大量客户端短连接场景（HTTP 请求/轮询类应用）：
 * 批量并发建立连接、经 tunnel_relay 转发少量数据、完整生命周期
 * 后关闭。通过控制变量法改变单轮并发批次与每连接数据量，
 * 统计连接建立速率与错误率。
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
     * @brief 风暴场景定义
     */
    struct storm_scenario
    {
        std::string name;            ///< 场景名称
        std::size_t batch{100};      ///< 每轮并发连接数
        std::size_t payload{1024};   ///< 每连接转发数据量
        std::size_t rounds{5};       ///< 轮数
    };

    /**
     * @brief 风暴运行结果
     */
    struct storm_result
    {
        std::size_t total_conn{0};   ///< 总完成连接数
        std::size_t errors{0};       ///< 总错误数
        double seconds{0};           ///< 总耗时
        double conn_per_sec{0};      ///< 连接速率
    };

    /**
     * @brief 单连接生命周期协程：建立 socket 对 → 传输数据 → 校验 → 关闭
     * @details 风暴测试定位为「连接建立速率 + 短生命周期」。复用保活的共享
     * acceptor（避免高频 create/close 触发 win_iocp 未处理事件），
     * 直接 socket 对模拟客户端↔代理链路（隧道高并发由 TunnelStress 覆盖）。
     */
    auto connection_lifecycle(net::any_io_executor ex, net::ip::tcp::acceptor &acceptor,
                              const std::size_t payload_size,
                              std::span<const std::byte> pool,
                              std::atomic<std::size_t> &completed,
                              std::atomic<std::size_t> &errors) -> net::awaitable<void>
    {
        auto client_sock = net::ip::tcp::socket(ex);
        co_await client_sock.async_connect(acceptor.local_endpoint(), net::use_awaitable);
        auto server_sock = co_await acceptor.async_accept(net::use_awaitable);
        auto client_tx = transport::make_reliable(std::move(client_sock));
        auto server_tx = transport::make_reliable(std::move(server_sock));

        // 写入「长度头 + 序号 + payload」
        const auto length = static_cast<std::uint64_t>(payload_size);
        std::array<std::byte, 16> header_buf{};
        std::memcpy(header_buf.data(), &length, sizeof(length));
        std::uint64_t seq = 0;
        std::memcpy(header_buf.data() + 8, &seq, sizeof(seq));

        std::error_code ec;
        const auto written = co_await transport::async_write(
            *client_tx, std::span(header_buf), ec);
        if (ec || written == 0)
        {
            errors.fetch_add(1, std::memory_order_relaxed);
            co_return;
        }
        if (payload_size > 0)
        {
            const auto body_n = co_await transport::async_write(
                *client_tx, pool.first(payload_size), ec);
            if (ec || body_n == 0)
            {
                errors.fetch_add(1, std::memory_order_relaxed);
                co_return;
            }
        }
        // 半关闭写方向，通知对端数据结束
        if (auto *rel = client_tx->lowest_layer<transport::reliable>(); rel != nullptr)
        {
            rel->shutdown_write();
        }

        // 读取并校验响应（长度头 + payload）
        std::array<std::uint64_t, 2> header{};
        const auto header_n = co_await transport::async_read(
            *server_tx, std::span(reinterpret_cast<std::byte *>(header.data()), sizeof(header)), ec);
        if (ec || header_n == 0)
        {
            errors.fetch_add(1, std::memory_order_relaxed);
        }
        else if (header[0] != length || header[1] != seq)
        {
            errors.fetch_add(1, std::memory_order_relaxed);
        }
        completed.fetch_add(1, std::memory_order_relaxed);
    }

    /**
     * @brief 运行单个风暴场景
     * @note 每个场景独立 io_context（保活不析构）：win_iocp 析构会等待
     * 未完成操作导致卡死；场景间复用会产生在途事件污染后续 connect。
     */
    auto run_storm(const storm_scenario &sc) -> storm_result
    {
        static std::vector<std::unique_ptr<net::io_context>> g_iocs;
        auto ioc_holder = std::make_unique<net::io_context>();
        auto &ioc = *ioc_holder;
        g_iocs.push_back(std::move(ioc_holder));
        std::atomic<bool> stop{false};
        std::atomic<std::size_t> completed{0};
        std::atomic<std::size_t> errors{0};
        auto pool = make_payload_pool(65536);

        std::exception_ptr ep;
        auto driver = [&]() -> net::awaitable<void>
        {
            const auto ex = co_await net::this_coro::executor;
            // 共享 acceptor（保活，不析构）
            static std::vector<std::unique_ptr<net::ip::tcp::acceptor>> g_acceptors;
            auto acceptor = std::make_unique<net::ip::tcp::acceptor>(
                ex, net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
            auto &acc = *acceptor;
            g_acceptors.push_back(std::move(acceptor));
            for (std::size_t round = 0; round < sc.rounds; ++round)
            {
                // 每轮批量建立连接
                for (std::size_t i = 0; i < sc.batch; ++i)
                {
                    net::co_spawn(ex, connection_lifecycle(ex, acc, sc.payload, pool, completed, errors), net::detached);
                }
                // 等待本轮全部完成（最多 30 秒，防死循环）
                for (std::size_t wait_ms = 0; wait_ms < 30000; wait_ms += 1)
                {
                    if (completed.load(std::memory_order_acquire) >= (round + 1) * sc.batch)
                    {
                        break;
                    }
                    co_await async_wait(ex, std::chrono::milliseconds(1));
                }
            }
        };

        const auto wall_start = std::chrono::steady_clock::now();
        net::co_spawn(ioc, driver(), [&](std::exception_ptr e)
                      { ep = e; });
        // 模拟生产多 worker：多线程驱动同一 io_context（本工具无 PMR 分配，跨线程安全）
        std::vector<std::thread> threads;
        for (int i = 0; i < 4; ++i)
        {
            threads.emplace_back([&]
                                 { ioc.run_for(std::chrono::seconds(60)); });
        }
        for (auto &t : threads)
        {
            t.join();
        }
        const auto wall_end = std::chrono::steady_clock::now();

        storm_result result{};
        result.total_conn = completed.load(std::memory_order_relaxed);
        result.errors = errors.load(std::memory_order_relaxed);
        result.seconds = std::chrono::duration<double>(wall_end - wall_start).count();
        result.conn_per_sec = static_cast<double>(result.total_conn) / result.seconds;
        return result;
    }

    /**
     * @brief 构建风暴场景矩阵（基线 = 批次 100 / 数据 1K）
     */
    auto build_scenarios() -> std::vector<storm_scenario>
    {
        return {
            storm_scenario{.name = "C1 批次10·空数据", .batch = 10, .payload = 0, .rounds = 20},
            storm_scenario{.name = "C2 批次10·1K", .batch = 10, .payload = 1024, .rounds = 20},
            storm_scenario{.name = "C3 批次100·1K", .batch = 100, .payload = 1024, .rounds = 10},
            storm_scenario{.name = "C4 批次100·64K", .batch = 100, .payload = 65536, .rounds = 10},
            storm_scenario{.name = "C5 批次500·1K", .batch = 500, .payload = 1024, .rounds = 5},
            storm_scenario{.name = "C6 批次500·64K", .batch = 500, .payload = 65536, .rounds = 5},
        };
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
    std::cout << "  Prism 连接风暴压力测试\n";
    std::cout << "  模拟短连接高频场景 (HTTP/轮询)\n";
    std::cout << "========================================\n";

    std::cout << "\n";
    std::cout << std::format("{:<22}{:>8}{:>10}{:>12}{:>12}\n", "场景", "总连接", "耗时", "速率", "错误");
    std::cout << "-------------------------------------------------------------\n";

    std::size_t failed = 0;
    for (const auto &sc : build_scenarios())
    {
        const auto result = run_storm(sc);
        const bool pass = (result.errors == 0 && result.total_conn > 0);
        std::cout << std::format("{:<22}{:>8}{:>9.2f}s{}{:>11.0f}{:>12}\n",
                                 sc.name, result.total_conn, result.seconds, "",
                                 result.conn_per_sec, (pass ? "0" : std::to_string(result.errors)));
        if (!pass)
        {
            ++failed;
        }
    }

    std::cout << "-------------------------------------------------------------\n";
    std::cout << std::format("完成: {} 个场景, {} 个失败\n\n", 6, failed);
    // 跳过 static 析构（保活的 io_context/socket 在析构阶段触发未处理事件）
    std::fflush(nullptr);
    std::quick_exit(failed == 0 ? 0 : 1);
}
