#include <forward-engine/memory/pool.hpp>
#include <forward-engine/memory/container.hpp>

#include "counting_resource.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <latch>
#include <string>
#include <thread>
#include <vector>

using namespace ngx;

namespace
{
    // 配置结构体
    struct stress_config
    {
        std::size_t threads = std::max<std::size_t>(1, std::thread::hardware_concurrency());
        std::size_t duration_sec = 5;
        std::size_t alloc_size = 128;
    };

    // 默认配置
    const stress_config DEFAULT_CONFIG = {
        .threads = 4,
        .duration_sec = 240,
        .alloc_size = 128,
    };

    // 线程统计结果
    struct thread_stats
    {
        std::uint64_t ops = 0;
        std::uint64_t bytes_allocated = 0;
        std::uint64_t peak_memory = 0;
    };

    // 模拟竞争工作线程
    void worker_thread(std::size_t thread_id, 
                       const stress_config& config, 
                       std::latch& start_latch,
                       std::atomic<bool>& stop_flag,
                       thread_stats& stats)
    {
        (void)thread_id;

        // 使用全局内存池来制造最大的锁竞争压力
        std::pmr::memory_resource* upstream = memory::system::global_pool();
        ngx::stress::counting_resource counter(upstream);
        std::pmr::memory_resource* mr = &counter;
        
        // 预分配载荷
        std::string payload_data(config.alloc_size, 'x');

        // 等待所有线程就绪
        start_latch.arrive_and_wait();

        while (!stop_flag.load(std::memory_order_relaxed))
        {
            // 紧凑循环：分配 -> 写入 -> 释放
            // 这会给分配器的锁机制带来最大压力
            for (int i = 0; i < 1000; ++i) 
            {
                memory::string s(mr);
                s.assign(payload_data); // 触发分配和写入
                // s 析构触发释放
                
                stats.ops++;
            }
        }

        stats.bytes_allocated = counter.bytes_allocated();
        stats.peak_memory = counter.peak_bytes_in_use();
    }
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    std::cout << ">>> ForwardEngine Pool Contention Stress Tool (Refactored) <<<" << std::endl;

    stress_config config = DEFAULT_CONFIG;

    std::cout << "Configuration:" << std::endl;
    std::cout << "  Threads:      " << config.threads << std::endl;
    std::cout << "  Duration:     " << config.duration_sec << " seconds" << std::endl;
    std::cout << "  Alloc Size:   " << config.alloc_size << " bytes" << std::endl;
    std::cout << "  Target:       Global Pool (High Contention)" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;

    std::vector<std::thread> threads;
    std::vector<thread_stats> all_stats(config.threads);
    std::latch start_latch(config.threads + 1);
    std::atomic<bool> stop_flag{false};

    std::cout << "Initializing " << config.threads << " threads..." << std::endl;

    for (std::size_t i = 0; i < config.threads; ++i)
    {
        threads.emplace_back(worker_thread, 
                             i, 
                             std::cref(config), 
                             std::ref(start_latch), 
                             std::ref(stop_flag), 
                             std::ref(all_stats[i]));
    }

    std::cout << "Starting contention test..." << std::endl;
    start_latch.arrive_and_wait();

    auto start_time = std::chrono::steady_clock::now();
    for (std::size_t s = 0; s < config.duration_sec; ++s)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Running... " << (s + 1) << "/" << config.duration_sec << "s" << std::endl;
    }

    std::cout << "Stopping threads..." << std::endl;
    stop_flag.store(true, std::memory_order_release);

    for (auto& t : threads)
    {
        if (t.joinable()) t.join();
    }

    thread_stats total_stats{};
    for (const auto& s : all_stats)
    {
        total_stats.ops += s.ops;
        total_stats.bytes_allocated += s.bytes_allocated;
        total_stats.peak_memory = std::max(total_stats.peak_memory, s.peak_memory);
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
    std::cout << "Peak Memory:    " << (total_stats.peak_memory / 1024) << " KB (Max single thread peak)" << std::endl;
    std::cout << "================================================" << std::endl;

    return 0;
}
