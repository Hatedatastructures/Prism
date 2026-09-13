/**
 * @file ConcurrentBench.cpp
 * @brief 多并发资源指针对比（Release）
 * @details 8 线程并发执行：
 * 1. 协议帧构建（BuildRequest）：Arena 复用 vs 每帧 malloc
 * 2. 协议握手路径模拟（多对象分配）：Arena vs 系统堆
 * 测量总耗时与 P50/P99 延迟分布。
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Foundation/Memory/Pool.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Socks5/Types.hpp>

using Clock = std::chrono::steady_clock;

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;

    auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   Clock::now().time_since_epoch())
            .count();
    }

    // ── 每线程任务：N 次帧构建 ──
    auto WorkerArena(const int Iterations, volatile std::size_t &TotalBytes) -> std::vector<std::int64_t>
    {
        Socks5::Request RequestValue;
        RequestValue.Ver = Socks5::Version;
        RequestValue.Cmd = Socks5::Command::Connect;
        RequestValue.Rsv = 0;
        RequestValue.Target.Type = Socks5::AddressType::Domain;
        RequestValue.Target.Host = "example.com";
        RequestValue.Target.Port = 443;

        Preview::Memory::SessionResource<> mem;
        typename Preview::Memory::SessionResource<>::Buffer<std::uint8_t> Buffer(mem.Arena());
        std::vector<std::int64_t> Latencies;
        Latencies.reserve(Iterations);
        for (int Index = 0; Index < Iterations; ++Index)
        {
            const auto Start = NowNs();
            Socks5::BuildRequest(RequestValue, Buffer);
            TotalBytes += Buffer.size();
            const auto Duration = NowNs() - Start;
            if (Index % 1000 == 0)
            {
                Latencies.push_back(Duration);
            }
        }
        return Latencies;
    }

    auto WorkerMalloc(const int Iterations, volatile std::size_t &TotalBytes) -> std::vector<std::int64_t>
    {
        Socks5::Request RequestValue;
        RequestValue.Ver = Socks5::Version;
        RequestValue.Cmd = Socks5::Command::Connect;
        RequestValue.Rsv = 0;
        RequestValue.Target.Type = Socks5::AddressType::Domain;
        RequestValue.Target.Host = "example.com";
        RequestValue.Target.Port = 443;

        std::vector<std::int64_t> Latencies;
        Latencies.reserve(Iterations);
        for (int Index = 0; Index < Iterations; ++Index)
        {
            const auto Start = NowNs();
            const auto Wire = Socks5::BuildRequest(RequestValue); // 返回式：每帧 malloc
            TotalBytes += Wire.size();
            const auto Duration = NowNs() - Start;
            if (Index % 1000 == 0)
            {
                Latencies.push_back(Duration);
            }
        }
        return Latencies;
    }

    auto Percentile(std::vector<std::int64_t> &Values, const double Probability) -> std::int64_t
    {
        std::sort(Values.begin(), Values.end());
        return Values[static_cast<std::size_t>(Values.size() * Probability)];
    }
} // namespace

auto main() -> int
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr int ThreadCount = 8;
    constexpr int IterationCount = 500000; // 每线程 50 万次

    // ── Arena 复用（资源指针）──
    {
        std::vector<std::thread> Threads;
        std::vector<std::vector<std::int64_t>> Latencies(ThreadCount);
        volatile std::size_t Sink = 0;
        const auto Start = NowNs();
        for (int Thread = 0; Thread < ThreadCount; ++Thread)
        {
            Threads.emplace_back([&, Thread]() { Latencies[Thread] = WorkerArena(IterationCount, Sink); });
        }
        for (auto &ThreadValue : Threads)
        {
            ThreadValue.join();
        }
        const auto Total = NowNs() - Start;
        std::vector<std::int64_t> All;
        for (auto &ThreadLatencies : Latencies)
        {
            All.insert(All.end(), ThreadLatencies.begin(), ThreadLatencies.end());
        }
        std::printf("Arena 复用  8线程 x %d次: 总 %8.2f ms  P50=%5.1f ns  P99=%6.1f ns  P999=%7.1f ns\n",
                     IterationCount, Total / 1e6, static_cast<double>(Percentile(All, 0.5)),
                     static_cast<double>(Percentile(All, 0.99)),
                     static_cast<double>(Percentile(All, 0.999)));
    }

    // ── 每帧 malloc（无资源指针）──
    {
        std::vector<std::thread> Threads;
        std::vector<std::vector<std::int64_t>> Latencies(ThreadCount);
        volatile std::size_t Sink = 0;
        const auto Start = NowNs();
        for (int Thread = 0; Thread < ThreadCount; ++Thread)
        {
            Threads.emplace_back([&, Thread]() { Latencies[Thread] = WorkerMalloc(IterationCount, Sink); });
        }
        for (auto &ThreadValue : Threads)
        {
            ThreadValue.join();
        }
        const auto Total = NowNs() - Start;
        std::vector<std::int64_t> All;
        for (auto &ThreadLatencies : Latencies)
        {
            All.insert(All.end(), ThreadLatencies.begin(), ThreadLatencies.end());
        }
        std::printf("每帧 malloc 8线程 x %d次: 总 %8.2f ms  P50=%5.1f ns  P99=%6.1f ns  P999=%7.1f ns\n",
                     IterationCount, Total / 1e6, static_cast<double>(Percentile(All, 0.5)),
                     static_cast<double>(Percentile(All, 0.99)),
                     static_cast<double>(Percentile(All, 0.999)));
    }
    return 0;
}
