#include <forward-engine/memory/pool.hpp>
#include <forward-engine/memory/container.hpp>

#include "counting_resource.hpp"

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

using namespace ngx;

namespace
{
    // 配置结构体
    struct stress_config
    {
        std::size_t threads = std::max<std::size_t>(1, std::thread::hardware_concurrency());
        std::size_t duration_sec = 10;
        std::size_t max_memory_gb = 32;
        std::size_t allocation_batch = 1000; // 每个线程每次分配的对象数量
        std::size_t min_alloc_size = 64;
        std::size_t max_alloc_size = 65536;
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

    struct stress_context
    {
        stress_config config;
        std::size_t effective_memory_limit = 0;
        std::size_t memory_limit_per_thread = 0;
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

    stress_context build_stress_context(const stress_config &config)
    {
        stress_context context{};
        context.config = config;
        context.effective_memory_limit = get_system_memory_limit(config.max_memory_gb);
        context.memory_limit_per_thread = context.effective_memory_limit / config.threads;
        return context;
    }

    /**
     * @brief 模拟负载工作线程
     * @param thread_id 线程ID
     * @param context 压力测试上下文
     * @param start_latch 启动门闩，用于同步所有线程
     * @param stop_flag 停止标志，用于控制线程退出
     * @param stats 线程统计结果引用
     */
    void worker_thread(std::size_t thread_id, const stress_context &context,
                       std::latch &start_latch, const std::atomic<bool> &stop_flag, thread_stats &stats)
    {
        // 1. 初始化内存资源
        memory::resource_pointer upstream = memory::system::thread_local_pool();
        ngx::stress::counting_resource counter(upstream);

        // 2. 等待所有线程就绪
        start_latch.arrive_and_wait();

        std::mt19937_64 rng(thread_id * 1234567 + std::random_device{}());
        std::uniform_int_distribution<std::size_t> size_dist(context.config.min_alloc_size, context.config.max_alloc_size);

        // 使用 vector 存储分配的对象，模拟实际持有内存
        std::vector<memory::string> keep_alive_objects;
        keep_alive_objects.reserve(context.config.allocation_batch);

        try
        {
            while (!stop_flag.load(std::memory_order_relaxed))
            {
                // 检查当前内存使用是否超限
                if (counter.bytes_in_use() >= context.memory_limit_per_thread)
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

        // 收集最终统计数据
        stats.bytes_allocated = counter.bytes_allocated();
        stats.bytes_deallocated = counter.bytes_deallocated();
        stats.peak_memory = counter.peak_bytes_in_use();

        // 对象会在 vector 析构时自动释放
    }

    /**
     * @brief 运行内存压力测试
     * @param context 压力测试上下文
     */
    void stress_test(const stress_context &context)
    {
        std::cout << std::format(">>> ForwardEngine 内存压力测试工具 <<<\n");

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
        std::vector<thread_stats> all_stats(context.config.threads);
        std::latch start_latch(context.config.threads + 1);
        std::atomic<bool> stop_flag{false};

        std::cout << std::format("正在初始化 {} 线程...\n", context.config.threads);

        for (std::size_t i = 0; i < context.config.threads; ++i)
        {
            threads.emplace_back(worker_thread, i,
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

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif
    // 1. 配置加载
    stress_config config;
    config.threads = 4;
    config.duration_sec = 10;
    config.max_memory_gb = 2;
    // config.allocation_batch = 1000; // 每个线程每次分配的对象数量

    stress_context context = build_stress_context(config);
    stress_test(context);
    return 0;
}
