/**
 * @file MemoryStress.cpp
 * @brief 多线程内存分配压力测试
 * @details 测试 PMR 内存分配器在高并发、大容量分配/释放场景下的稳定性，
 * 模拟随机大小的内存分配与释放，验证 OOM 处理和内存回收机制。
 */

#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>

#include "CountingResource.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <latch>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

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
        std::size_t duration_sec = 10;
        std::size_t max_memory_gb = 32;
        std::size_t allocation_batch = 1000;
        std::size_t min_alloc_size = 64;
        std::size_t max_alloc_size = 65536;
    };

    // 线程统计结果
    struct ThreadStats
    {
        std::uint64_t ops = 0;
        std::uint64_t bytes_allocated = 0;
        std::uint64_t bytes_deallocated = 0;
        std::uint64_t peak_memory = 0;
        bool oom_error = false;
    };

    struct StressContext
    {
        StressConfig config;
        std::size_t effective_memory_limit = 0;
        std::size_t memory_limit_per_thread = 0;
    };

    // 获取系统可用内存限制
    std::size_t GetSystemMemoryLimit(std::size_t requested_gb)
    {
        const std::size_t requested_bytes = requested_gb * 1024ULL * 1024ULL * 1024ULL;
#if defined(_WIN32)
        MEMORYSTATUSEX status{};
        status.dwLength = sizeof(status);
        if (GlobalMemoryStatusEx(&status))
        {
            const std::size_t safe_limit = static_cast<std::size_t>(status.ullAvailPhys * 0.85);
            if (safe_limit > 0 && safe_limit < requested_bytes)
            {
                return safe_limit;
            }
        }
#endif
        return requested_bytes;
    }

    StressContext BuildStressContext(const StressConfig &config)
    {
        StressContext context{};
        context.config = config;
        context.effective_memory_limit = GetSystemMemoryLimit(config.max_memory_gb);
        context.memory_limit_per_thread = context.effective_memory_limit / config.threads;
        return context;
    }

    /**
     * @brief 模拟负载工作线程
     */
    void WorkerThread(const std::size_t thread_id, const StressContext &context,
                      std::latch &start_latch, const std::atomic<bool> &stop_flag, ThreadStats &stats)
    {
        memory::resource_pointer upstream = memory::system::thread_local_pool();
        psm::stress::counting_resource counter(upstream);

        start_latch.arrive_and_wait();

        std::mt19937_64 rng(thread_id * 1234567 + std::random_device{}());
        std::uniform_int_distribution<std::size_t> size_dist(context.config.min_alloc_size, context.config.max_alloc_size);

        std::vector<memory::string> keep_alive_objects;
        keep_alive_objects.reserve(context.config.allocation_batch);

        try
        {
            while (!stop_flag.load(std::memory_order_relaxed))
            {
                if (counter.bytes_in_use() >= context.memory_limit_per_thread)
                {
                    keep_alive_objects.resize(keep_alive_objects.size() / 2);
                    std::this_thread::yield();
                    continue;
                }

                for (std::size_t i = 0; i < 100; ++i)
                {
                    const std::size_t size = size_dist(rng);
                    memory::string s(&counter);
                    s.resize(size, static_cast<char>(rng()));
                    keep_alive_objects.push_back(std::move(s));
                    stats.ops++;
                }

                if (keep_alive_objects.size() > context.config.allocation_batch)
                {
                    std::size_t remove_count = keep_alive_objects.size() / 3;
                    keep_alive_objects.erase(keep_alive_objects.begin(), keep_alive_objects.begin() + remove_count);
                }
            }
        }
        catch (const std::bad_alloc &)
        {
            stats.oom_error = true;
        }

        stats.bytes_allocated = counter.bytes_allocated();
        stats.bytes_deallocated = counter.bytes_deallocated();
        stats.peak_memory = counter.peak_bytes_in_use();
    }

    /**
     * @brief 运行内存压力测试
     */
    void StressTest(const StressContext &context)
    {
        std::cout << std::format(">>> Prism 内存压力测试工具 <<<\n");

        std::cout << "------------------------------------------------" << std::endl;
        std::cout << std::format("{:<24}{}\n", "配置:", "值");
        std::cout << std::format("{:<24}{}\n", "  线程数:", context.config.threads);
        std::cout << std::format("{:<24}{} 秒\n", "  持续时间:", context.config.duration_sec);
        std::cout << std::format("{:<24}{} GB (系统限制后: {} MB)\n",
                                 "  最大内存:", context.config.max_memory_gb, (context.effective_memory_limit / 1024 / 1024));
        std::cout << std::format("{:<24}{}\n", "  每个线程每次分配的对象数量:", context.config.allocation_batch);
        std::cout << std::format("{:<24}{} - {} bytes\n", "  每个线程每次分配的对象大小范围:", context.config.min_alloc_size,
                                 context.config.max_alloc_size);
        std::cout << "------------------------------------------------" << std::endl;

        std::vector<std::jthread> threads;
        std::vector<ThreadStats> all_stats(context.config.threads);
        std::latch start_latch(context.config.threads + 1);
        std::atomic<bool> stop_flag{false};

        std::cout << std::format("正在初始化 {} 线程...\n", context.config.threads);

        for (std::size_t i = 0; i < context.config.threads; ++i)
        {
            threads.emplace_back(WorkerThread, i,
                                 std::cref(context), std::ref(start_latch),
                                 std::ref(stop_flag), std::ref(all_stats[i]));
        }

        std::cout << std::format("  {} 线程初始化完成...\n", context.config.threads);
        std::cout << std::format("  正在启动压力测试...\n");
        start_latch.arrive_and_wait();

        auto start_time = std::chrono::steady_clock::now();
        for (std::size_t s = 0; s < context.config.duration_sec; ++s)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::cout << std::format("  已运行 {} 秒...\n", (s + 1));
        }

        stop_flag.store(true, std::memory_order_release);

        for (auto &t : threads)
        {
            if (t.joinable())
            {
                t.join();
            }
        }

        ThreadStats total_stats{};
        for (const auto &s : all_stats)
        {
            total_stats.ops += s.ops;
            total_stats.bytes_allocated += s.bytes_allocated;
            total_stats.bytes_deallocated += s.bytes_deallocated;
            total_stats.peak_memory += s.peak_memory;
            if (s.oom_error)
                total_stats.oom_error = true;
        }

        auto end_time = std::chrono::steady_clock::now();
        std::chrono::duration<double> duration = end_time - start_time;
        double actual_duration = duration.count();

        std::cout << "\n================================================" << std::endl;
        std::cout << "                最终报告                        " << std::endl;
        std::cout << "================================================" << std::endl;
        std::cout << std::format("{:<12}{:.2f} 秒\n", "持续时间:", actual_duration);
        std::cout << std::format("{:<12}{}\n", "总操作数:", total_stats.ops);
        std::cout << std::format("{:<12}{} 次/秒\n", "吞吐量:", static_cast<std::uint64_t>(total_stats.ops / actual_duration));
        std::cout << std::format("{:<12}{} MB\n", "总分配:", (total_stats.bytes_allocated / 1024 / 1024));
        std::cout << std::format("{:<12}{} MB (线程峰值之和)\n", "峰值内存:", (total_stats.peak_memory / 1024 / 1024));
        std::cout << std::format("{:<12}{}\n", "OOM 错误:", (total_stats.oom_error ? "是" : "否"));
        std::cout << "================================================" << std::endl;
    }
}

int main(const int argc, char **argv)
{
    (void)argc;
    (void)argv;

#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif
    StressConfig config;
    config.threads = 4;
    config.duration_sec = 10;
    config.max_memory_gb = 2;

    StressContext context = BuildStressContext(config);
    StressTest(context);
    return 0;
}
