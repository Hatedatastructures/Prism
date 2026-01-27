#include <forward-engine/memory/pool.hpp>
#include <forward-engine/memory/container.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <latch>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>
#include <numeric>

using namespace ngx;

namespace
{
    // 配置结构体
    struct stress_config
    {
        std::size_t iterations = 20000;
        std::size_t alloc_per_reset = 64; // 每次重置前分配多少个对象
        std::size_t object_size = 1024;   // 每个对象多大
    };

    // 默认配置
    const stress_config DEFAULT_CONFIG = {
        .iterations = 50000,
        .alloc_per_reset = 128,
        .object_size = 256,
    };

    // 统计结果
    struct latency_stats
    {
        std::uint64_t total_ns = 0;
        std::uint64_t min_ns = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t max_ns = 0;
        std::uint64_t count = 0;
    };

    void run_test(const stress_config& config)
    {
        memory::frame_arena arena;
        std::pmr::memory_resource* mr = arena.get();
        std::string payload(config.object_size, 'x');

        latency_stats stats;
        
        // 预热
        for(int i=0; i<100; ++i) {
            arena.reset();
            memory::string s(mr);
            s.assign(payload);
        }

        std::cout << "Starting latency test..." << std::endl;
        std::cout << "  Iterations:      " << config.iterations << std::endl;
        std::cout << "  Alloc per iter:  " << config.alloc_per_reset << std::endl;
        std::cout << "  Object Size:     " << config.object_size << " bytes" << std::endl;
        std::cout << "------------------------------------------------" << std::endl;

        auto total_start = std::chrono::steady_clock::now();
        std::size_t progress_step = config.iterations / 10;

        for (std::size_t i = 0; i < config.iterations; ++i)
        {
            if (i > 0 && i % progress_step == 0) {
                std::cout << "Progress: " << (i * 100 / config.iterations) << "%" << std::endl;
            }

            auto t0 = std::chrono::steady_clock::now();

            // 1. 重置 Arena (极快)
            arena.reset();

            // 2. 执行一组分配
            for (std::size_t k = 0; k < config.alloc_per_reset; ++k)
            {
                memory::string s(mr);
                s.assign(payload);
                // 模拟使用
                volatile char c = s[0];
                (void)c;
            }

            auto t1 = std::chrono::steady_clock::now();
            std::uint64_t ns = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());

            stats.total_ns += ns;
            stats.min_ns = std::min(stats.min_ns, ns);
            stats.max_ns = std::max(stats.max_ns, ns);
            stats.count++;
        }

        auto total_end = std::chrono::steady_clock::now();
        double total_sec = std::chrono::duration<double>(total_end - total_start).count();
        double avg_ns = static_cast<double>(stats.total_ns) / stats.count;

        std::cout << "\n================================================" << std::endl;
        std::cout << "                FINAL REPORT                    " << std::endl;
        std::cout << "================================================" << std::endl;
        std::cout << "Total Duration: " << std::fixed << std::setprecision(2) << total_sec << " s" << std::endl;
        std::cout << "Avg Latency:    " << std::fixed << std::setprecision(2) << avg_ns << " ns/batch" << std::endl;
        std::cout << "Min Latency:    " << stats.min_ns << " ns" << std::endl;
        std::cout << "Max Latency:    " << stats.max_ns << " ns" << std::endl;
        std::cout << "Throughput:     " << static_cast<std::uint64_t>(stats.count / total_sec) << " batches/sec" << std::endl;
        std::cout << "================================================" << std::endl;
    }
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    std::cout << ">>> ForwardEngine Arena Overflow Stress Tool (Refactored) <<<" << std::endl;

    run_test(DEFAULT_CONFIG);

    return 0;
}
