#include <forward-engine/memory/pool.hpp>
#include <forward-engine/memory/container.hpp>

#include "counting_resource.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <latch>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

#if defined(_WIN32)
#include <windows.h>
#endif

using namespace ngx;

namespace
{
    // 配置结构体
    struct stress_config
    {
        std::size_t threads = std::max<std::size_t>(1, std::thread::hardware_concurrency());
        std::size_t duration_sec = 10;
        std::size_t max_memory_gb = 32;
        std::size_t allocation_batch = 1000;
        std::size_t min_alloc_size = 64;
        std::size_t max_alloc_size = 65536;
    };

    // 默认配置
    constexpr stress_config DEFAULT_CONFIG = {
        .threads = 4,
        .duration_sec = 28800,
        .max_memory_gb = 32,
    };

    // 线程统计结果
    struct thread_stats
    {
        std::uint64_t ops = 0;
        std::uint64_t bytes_allocated = 0;
        std::uint64_t bytes_deallocated = 0;
        std::uint64_t peak_memory = 0;
        bool oom_error = false;
    };

    // 获取系统可用内存限制
    std::size_t get_system_memory_limit(std::size_t requested_gb)
    {
        const std::size_t requested_bytes = requested_gb * 1024ULL * 1024ULL * 1024ULL;
#if defined(_WIN32)
        MEMORYSTATUSEX status{};
        status.dwLength = sizeof(status);
        if (GlobalMemoryStatusEx(&status))
        {
            // 限制为物理内存的 85%，防止系统卡死
            std::size_t safe_limit = static_cast<std::size_t>(status.ullAvailPhys * 0.85);
            if (safe_limit > 0 && safe_limit < requested_bytes)
            {
                return safe_limit;
            }
        }
#endif
        return requested_bytes;
    }

    // 模拟负载工作线程
    void worker_thread(std::size_t thread_id,
                       const stress_config &config,
                       std::latch &start_latch,
                       const std::atomic<bool> &stop_flag,
                       thread_stats &stats,
                       std::size_t memory_limit_per_thread)
    {
        // 1. 初始化内存资源
        std::pmr::memory_resource *upstream = memory::system::thread_local_pool();
        ngx::stress::counting_resource counter(upstream);

        // 2. 等待所有线程就绪
        start_latch.arrive_and_wait();

        std::mt19937_64 rng(thread_id * 1234567 + std::random_device{}());
        std::uniform_int_distribution<std::size_t> size_dist(config.min_alloc_size, config.max_alloc_size);

        // 使用 vector 存储分配的对象，模拟实际持有内存
        std::vector<memory::string> keep_alive_objects;
        keep_alive_objects.reserve(config.allocation_batch);

        try
        {
            while (!stop_flag.load(std::memory_order_relaxed))
            {
                // 检查当前内存使用是否超限
                if (counter.bytes_in_use() >= memory_limit_per_thread)
                {
                    // 内存满了，清理一半
                    keep_alive_objects.resize(keep_alive_objects.size() / 2);
                    // 稍微休眠一下，避免疯狂自旋
                    std::this_thread::yield();
                    continue;
                }

                // 执行一批分配
                for (std::size_t i = 0; i < 100; ++i)
                {
                    std::size_t size = size_dist(rng);
                    memory::string s(&counter);
                    // 写入数据确保内存被实际 commit
                    s.resize(size, static_cast<char>(rng()));
                    keep_alive_objects.push_back(std::move(s));

                    stats.ops++;
                }

                // 随机释放一些对象，模拟真实的内存波动
                if (keep_alive_objects.size() > config.allocation_batch)
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

        // 收集最终统计数据
        stats.bytes_allocated = counter.bytes_allocated();
        stats.bytes_deallocated = counter.bytes_deallocated();
        stats.peak_memory = counter.peak_bytes_in_use();

        // 对象会在 vector 析构时自动释放
    }
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    std::cout << ">>> ForwardEngine Memory Stress Tool (Refactored) <<<" << std::endl;

    // 1. 配置加载
    stress_config config = DEFAULT_CONFIG;
    std::size_t effective_memory_limit = get_system_memory_limit(config.max_memory_gb);
    std::size_t memory_per_thread = effective_memory_limit / config.threads;

    std::cout << "Configuration:" << std::endl;
    std::cout << "  Threads:      " << config.threads << std::endl;
    std::cout << "  Duration:     " << config.duration_sec << " seconds" << std::endl;
    std::cout << "  Max Memory:   " << config.max_memory_gb << " GB (System Limit Applied: "
              << (effective_memory_limit / 1024 / 1024) << " MB)" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;

    // 2. 线程准备
    std::vector<std::thread> threads;
    std::vector<thread_stats> all_stats(config.threads);
    std::latch start_latch(config.threads + 1); // +1 for main thread
    std::atomic<bool> stop_flag{false};

    std::cout << "Initializing " << config.threads << " threads..." << std::endl;

    for (std::size_t i = 0; i < config.threads; ++i)
    {
        threads.emplace_back(worker_thread,
                             i,
                             std::cref(config),
                             std::ref(start_latch),
                             std::ref(stop_flag),
                             std::ref(all_stats[i]),
                             memory_per_thread);
    }

    // 3. 开始测试
    std::cout << "Starting stress test..." << std::endl;
    start_latch.arrive_and_wait(); // 同步启动所有线程

    // 4. 监控循环
    auto start_time = std::chrono::steady_clock::now();
    for (std::size_t s = 0; s < config.duration_sec; ++s)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Running... " << (s + 1) << "/" << config.duration_sec << "s" << std::endl;
    }

    // 5. 停止并回收
    std::cout << "Stopping threads..." << std::endl;
    stop_flag.store(true, std::memory_order_release);

    for (auto &t : threads)
    {
        if (t.joinable())
            t.join();
    }

    // 6. 汇总报告
    thread_stats total_stats{};
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
    double actual_duration = std::chrono::duration<double>(end_time - start_time).count();

    std::cout << "\n================================================" << std::endl;
    std::cout << "                FINAL REPORT                    " << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << "Duration:       " << std::fixed << std::setprecision(2) << actual_duration << " s" << std::endl;
    std::cout << "Total Ops:      " << total_stats.ops << std::endl;
    std::cout << "Throughput:     " << static_cast<std::uint64_t>(total_stats.ops / actual_duration) << " ops/sec" << std::endl;
    std::cout << "Total Alloc:    " << (total_stats.bytes_allocated / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Peak Memory:    " << (total_stats.peak_memory / 1024 / 1024) << " MB (Sum of thread peaks)" << std::endl;
    std::cout << "OOM Errors:     " << (total_stats.oom_error ? "YES" : "NO") << std::endl;
    std::cout << "================================================" << std::endl;

    return 0;
}
