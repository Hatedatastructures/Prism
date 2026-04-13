/**
 * @file PoolContentionStress.cpp
 * @brief 内存池锁竞争压力测试
 * @details 多线程高频率分配/释放，专门测试全局内存池在极端竞争下的表现。
 */

#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>

#include "CountingResource.hpp"

#include <atomic>
#include <chrono>
#include <format>
#include <iostream>
#include <latch>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

using namespace psm;

namespace
{
    // 配置结构体
    struct StressConfig
    {
        std::size_t threads = std::max<std::size_t>(1, std::thread::hardware_concurrency());
        std::size_t duration_sec = 5;
        std::size_t alloc_size = 128;
    };

    // 默认配置
    constexpr StressConfig DEFAULT_STRESS_CONFIG = {
        .threads = 4,
        .duration_sec = 10,
        .alloc_size = 128,
    };

    // 线程统计结果
    struct ThreadStats
    {
        std::uint64_t ops = 0;
        std::uint64_t bytes_allocated = 0;
        std::uint64_t peak_memory = 0;
    };

    // 模拟竞争工作线程
    void WorkerThread(const std::size_t thread_id,
                      const StressConfig &config,
                      std::latch &start_latch,
                      const std::atomic<bool> &stop_flag,
                      ThreadStats &stats)
    {
        (void)thread_id;

        std::pmr::memory_resource *upstream = memory::system::global_pool();
        stress::counting_resource counter(upstream);
        std::pmr::memory_resource *mr = &counter;

        std::string payload_data(config.alloc_size, 'x');

        start_latch.arrive_and_wait();

        while (!stop_flag.load(std::memory_order_relaxed))
        {
            for (int i = 0; i < 1000; ++i)
            {
                memory::string s(mr);
                s.assign(payload_data);
                stats.ops++;
            }
        }

        stats.bytes_allocated = counter.bytes_allocated();
        stats.peak_memory = counter.peak_bytes_in_use();
    }
}

int main(const int argc, char **argv)
{
    (void)argc;
    (void)argv;
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::cout << ">>> Prism 内存池竞争压力测试工具 <<<" << std::endl;

    StressConfig config = DEFAULT_STRESS_CONFIG;

    std::cout << "------------------------------------------------" << std::endl;
    std::cout << std::format("{:<24}{}\n", "配置:", "值");
    std::cout << std::format("{:<24}{}\n", "  线程数:", config.threads);
    std::cout << std::format("{:<24}{} 秒\n", "  持续时间:", config.duration_sec);
    std::cout << std::format("{:<24}{} 字节\n", "  分配大小:", config.alloc_size);
    std::cout << std::format("{:<24}{}\n", "  目标:", "全局池（高竞争）");
    std::cout << "------------------------------------------------" << std::endl;

    std::vector<std::thread> threads;
    std::vector<ThreadStats> all_stats(config.threads);
    std::latch start_latch(config.threads + 1);
    std::atomic<bool> stop_flag{false};

    std::cout << std::format("正在初始化 {} 线程...\n", config.threads);

    for (std::size_t i = 0; i < config.threads; ++i)
    {
        threads.emplace_back(WorkerThread,
                             i,
                             std::cref(config),
                             std::ref(start_latch),
                             std::ref(stop_flag),
                             std::ref(all_stats[i]));
    }

    std::cout << std::format("正在启动竞争测试...\n");
    start_latch.arrive_and_wait();

    auto start_time = std::chrono::steady_clock::now();
    for (std::size_t s = 0; s < config.duration_sec; ++s)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << std::format("已运行 {} / {} 秒...\n", (s + 1), config.duration_sec);
    }

    std::cout << "正在停止线程..." << std::endl;
    stop_flag.store(true, std::memory_order_release);

    for (auto &t : threads)
    {
        if (t.joinable())
            t.join();
    }

    ThreadStats total_stats{};
    for (const auto &s : all_stats)
    {
        total_stats.ops += s.ops;
        total_stats.bytes_allocated += s.bytes_allocated;
        total_stats.peak_memory = std::max(total_stats.peak_memory, s.peak_memory);
    }

    auto end_time = std::chrono::steady_clock::now();
    double actual_duration = std::chrono::duration<double>(end_time - start_time).count();

    std::cout << "\n================================================" << std::endl;
    std::cout << "                最终报告                        " << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << std::format("{:<12}{:.2f} 秒\n", "持续时间:", actual_duration);
    std::cout << std::format("{:<12}{}\n", "总操作数:", total_stats.ops);
    std::cout << std::format("{:<12}{} 次/秒\n", "吞吐量:", static_cast<std::uint64_t>(total_stats.ops / actual_duration));
    std::cout << std::format("{:<12}{} MB\n", "总分配:", (total_stats.bytes_allocated / 1024 / 1024));
    std::cout << std::format("{:<12}{} KB (单线程峰值最大值)\n", "峰值内存:", (total_stats.peak_memory / 1024));
    std::cout << "================================================" << std::endl;

    return 0;
}
