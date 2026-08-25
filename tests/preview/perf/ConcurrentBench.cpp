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

#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Memory/Pool.hpp>
#include <common/Protocols/Socks5/Codec.hpp>
#include <common/Protocols/Socks5/Types.hpp>

using clk = std::chrono::steady_clock;

namespace
{
    auto now_ns() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
    }

    // ── 每线程任务：N 次帧构建 ──
    auto worker_arena(const int iters, volatile std::size_t &g) -> std::vector<std::int64_t>
    {
        using namespace Preview::Socks5;
        Request req;
        req.Ver = Version;
        req.Cmd = Command::Connect;
        req.Rsv = 0;
        req.Target.Type = AddressType::Domain;
        req.Target.Host = "example.com";
        req.Target.Port = 443;

        Preview::Memory::SessionResource<> mem;
        typename Preview::Memory::SessionResource<>::Buffer<std::uint8_t> buf(mem.Arena());
        std::vector<std::int64_t> lat;
        lat.reserve(iters);
        for (int i = 0; i < iters; ++i)
        {
            const auto t0 = now_ns();
            BuildRequest(req, buf); g += buf.size();
            const auto d = now_ns() - t0;
            if (i % 1000 == 0)
            {
                lat.push_back(d);
            }
        }
        return lat;
    }

    auto worker_malloc(const int iters, volatile std::size_t &g) -> std::vector<std::int64_t>
    {
        using namespace Preview::Socks5;
        Request req;
        req.Ver = Version;
        req.Cmd = Command::Connect;
        req.Rsv = 0;
        req.Target.Type = AddressType::Domain;
        req.Target.Host = "example.com";
        req.Target.Port = 443;

        std::vector<std::int64_t> lat;
        lat.reserve(iters);
        for (int i = 0; i < iters; ++i)
        {
            const auto t0 = now_ns();
            const auto wire = BuildRequest(req); // 返回式：每帧 malloc
            g += wire.size();
            const auto d = now_ns() - t0;
            if (i % 1000 == 0)
            {
                lat.push_back(d);
            }
        }
        return lat;
    }

    auto Percentile(std::vector<std::int64_t> &v, const double p) -> std::int64_t
    {
        std::sort(v.begin(), v.end());
        return v[static_cast<std::size_t>(v.size() * p)];
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr int kThreads = 8;
    constexpr int kIters = 500000; // 每线程 50 万次

    // ── Arena 复用（资源指针）──
    {
        std::vector<std::thread> ts;
        std::vector<std::vector<std::int64_t>> lats(kThreads);
        volatile std::size_t sink = 0;
        const auto t0 = now_ns();
        for (int t = 0; t < kThreads; ++t)
        {
            ts.emplace_back([&, t]() { lats[t] = worker_arena(kIters, sink); });
        }
        for (auto &th : ts)
        {
            th.join();
        }
        const auto Total = now_ns() - t0;
        std::vector<std::int64_t> All;
        for (auto &l : lats)
        {
            All.insert(All.end(), l.begin(), l.end());
        }
        std::printf("Arena 复用  8线程 x %d次: 总 %8.2f ms  P50=%5.1f ns  P99=%6.1f ns  P999=%7.1f ns\n",
                    kIters, Total / 1e6, Percentile(All, 0.5), Percentile(All, 0.99),
                    Percentile(All, 0.999));
    }

    // ── 每帧 malloc（无资源指针）──
    {
        std::vector<std::thread> ts;
        std::vector<std::vector<std::int64_t>> lats(kThreads);
        volatile std::size_t sink = 0;
        const auto t0 = now_ns();
        for (int t = 0; t < kThreads; ++t)
        {
            ts.emplace_back([&, t]() { lats[t] = worker_malloc(kIters, sink); });
        }
        for (auto &th : ts)
        {
            th.join();
        }
        const auto Total = now_ns() - t0;
        std::vector<std::int64_t> All;
        for (auto &l : lats)
        {
            All.insert(All.end(), l.begin(), l.end());
        }
        std::printf("每帧 malloc 8线程 x %d次: 总 %8.2f ms  P50=%5.1f ns  P99=%6.1f ns  P999=%7.1f ns\n",
                    kIters, Total / 1e6, Percentile(All, 0.5), Percentile(All, 0.99),
                    Percentile(All, 0.999));
    }
    return 0;
}
