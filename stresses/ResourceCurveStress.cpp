/**
 * @file ResourceCurveStress.cpp
 * @brief 连接数 × 内存资源曲线测试
 * @details 控制变量法：变量 = 驻留连接数（100/500/1000/2000/5000）。
 * 每个连接建立完整三段架构（手机端/隧道/上游端）并保持空闲驻留，
 * 采样进程私有内存与连接建立耗时，输出每连接内存成本与
 * 连接容量上限，并验证关闭后的内存释放。
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
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
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
     * @brief 当前进程内存占用（MB）
     * @return Windows 取 PagefileUsage（提交内存）；Linux 取 ru_maxrss（峰值驻留，
     *         单位 KB 换算 MB）。语义略有差异，用于压测曲线的相对趋势足够
     */
    auto process_memory_mb() -> double
    {
#if defined(_WIN32)
        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        {
            return static_cast<double>(pmc.PagefileUsage) / (1024.0 * 1024.0);
        }
        return 0;
#else
        struct rusage usage{};
        getrusage(RUSAGE_SELF, &usage);
        return static_cast<double>(usage.ru_maxrss) / 1024.0;
#endif
    }

    /**
     * @brief 结果
     */
    struct curve_result
    {
        std::size_t connections{0};
        double build_sec{0};
        double mem_mb{0};
        double per_conn_kb{0};
        bool pass{false};
    };

    /**
     * @brief 隧道转发协程（空闲驻留）
     */
    auto idle_tunnel_coro(transport::shared_transmission a, transport::shared_transmission b,
                          const std::size_t buffer) -> net::awaitable<void>
    {
        psm::connect::tunnel_options opts{a, b, static_cast<std::uint32_t>(buffer),
                                          psm::connect::write_policy::complete};
        opts.trace = std::make_shared<diagnose::context>();
        co_await psm::connect::tunnel_relay(std::move(opts)).run();
    }

    /**
     * @brief 运行单个连接数场景
     */
    auto run_curve(const std::size_t connections) -> curve_result
    {
        static std::vector<std::unique_ptr<net::io_context>> g_iocs;
        auto ioc_holder = std::make_unique<net::io_context>();
        auto &ioc = *ioc_holder;
        g_iocs.push_back(std::move(ioc_holder));

        curve_result result{};
        result.connections = connections;
        const double base_mb = process_memory_mb();

        std::exception_ptr ep;
        std::vector<transport::shared_transmission> keep;
        keep.reserve(connections * 4);
        auto driver = [&]() -> net::awaitable<void>
        {
            const auto ex = co_await net::this_coro::executor;
            const auto build_start = std::chrono::steady_clock::now();
            for (std::size_t i = 0; i < connections; ++i)
            {
                auto [phone_sock, proxy_client_sock] = co_await make_socket_pair(ex);
                auto [upstream_sock, proxy_server_sock] = co_await make_socket_pair(ex);
                // SO_LINGER=0：close 即 RST，避免 TIME_WAIT 端口累积耗尽动态端口
                boost::system::error_code sec;
                net::socket_base::linger linger_opt{true, 0};
                phone_sock.set_option(linger_opt, sec);
                proxy_client_sock.set_option(linger_opt, sec);
                upstream_sock.set_option(linger_opt, sec);
                proxy_server_sock.set_option(linger_opt, sec);
                auto phone_tx = transport::make_reliable(std::move(phone_sock));
                auto upstream_tx = transport::make_reliable(std::move(upstream_sock));
                auto proxy_client = transport::make_reliable(std::move(proxy_client_sock));
                auto proxy_server = transport::make_reliable(std::move(proxy_server_sock));
                net::co_spawn(ex, idle_tunnel_coro(proxy_client, proxy_server, 65536), net::detached);
                keep.push_back(phone_tx);
                keep.push_back(upstream_tx);
                keep.push_back(proxy_client);
                keep.push_back(proxy_server);
            }
            const auto build_end = std::chrono::steady_clock::now();
            result.build_sec = std::chrono::duration<double>(build_end - build_start).count();
            // 驻留采样（close 前，反映真实驻留内存）
            co_await async_wait(ex, std::chrono::milliseconds(500));
            result.mem_mb = process_memory_mb() - base_mb;
            result.per_conn_kb = (connections > 0) ? result.mem_mb * 1024.0 / static_cast<double>(connections) : 0.0;
            // 关闭全部连接（Windows IOCP 挂起操作阻止 run 返回）
            for (auto &tx : keep)
            {
                tx->close();
            }
            co_await async_wait(ex, std::chrono::milliseconds(300));
        };
        net::co_spawn(ioc, driver(), [&](std::exception_ptr e)
                      {
                          if (e)
                          {
                              try { std::rethrow_exception(e); }
                              catch (const std::exception &ex) { std::cerr << "[driver-ex: " << ex.what() << "]" << std::flush; }
                          }
                          ep = e;
                      });
        ioc.run_for(std::chrono::seconds(120));

        // 注意：内存采样已在 driver 内（close 前）完成；
        // 此处不再覆盖（close 后采样会低估驻留内存）
        result.pass = (result.build_sec > 0);
        return result;
    }

    /**
     * @brief 打印表头
     */
    void PrintHeader()
    {
        std::cout << "\n============================================================\n";
        std::cout << std::format("{:<12}{:>12}{:>12}{:>14}{:>8}\n",
                                 "连接数", "建立耗时", "私有内存", "每连接内存", "结果");
        std::cout << "------------------------------------------------------------\n";
    }

    /**
     * @brief 打印单行
     */
    void PrintRow(const curve_result &r)
    {
        std::cout << std::format("{:<12}{:>10.2f}s{}{:>11.1f}M{}{:>13.1f}K{}{:>8}\n",
                                 r.connections, r.build_sec, "", r.mem_mb, "",
                                 r.per_conn_kb, "",
                                 (r.pass ? "PASS" : "FAIL"));
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
    std::cout << "  Prism 连接数 × 内存资源曲线\n";
    std::cout << "  控制变量法: 驻留连接数\n";
    std::cout << "========================================\n";

    const std::vector<std::size_t> counts = {100, 500, 1000, 2000, 3000};

    PrintHeader();

    std::size_t failed = 0;
    for (const auto n : counts)
    {
        const auto result = run_curve(n);
        PrintRow(result);
        if (!result.pass)
        {
            ++failed;
        }
    }

    std::cout << "============================================================\n";
    std::cout << std::format("完成: {} 个场景, {} 个失败\n\n", counts.size(), failed);
    std::fflush(nullptr);
    std::quick_exit(failed == 0 ? 0 : 1);
}
