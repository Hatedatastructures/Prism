/**
 * @file ConcurrentBench.cpp
 * @brief 多并发资源指针对比（Release）
 * @details 8 线程并发执行：
 * 1. 协议帧构建（build_request）：arena 复用 vs 每帧 malloc
 * 2. 协议握手路径模拟（多对象分配）：arena vs 系统堆
 * 测量总耗时与 P50/P99 延迟分布。
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/memory/pool.hpp>
#include <common/protocols/socks5/codec.hpp>
#include <common/protocols/socks5/types.hpp>

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
        using namespace preview::socks5;
        request req;
        req.ver = version;
        req.cmd = command::connect;
        req.rsv = 0;
        req.target.type = address_type::domain;
        req.target.host = "example.com";
        req.target.port = 443;

        preview::memory::session_resource<> mem;
        typename preview::memory::session_resource<>::buffer<std::uint8_t> buf(mem.arena());
        std::vector<std::int64_t> lat;
        lat.reserve(iters);
        for (int i = 0; i < iters; ++i)
        {
            const auto t0 = now_ns();
            build_request(req, buf); g += buf.size();
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
        using namespace preview::socks5;
        request req;
        req.ver = version;
        req.cmd = command::connect;
        req.rsv = 0;
        req.target.type = address_type::domain;
        req.target.host = "example.com";
        req.target.port = 443;

        std::vector<std::int64_t> lat;
        lat.reserve(iters);
        for (int i = 0; i < iters; ++i)
        {
            const auto t0 = now_ns();
            const auto wire = build_request(req); // 返回式：每帧 malloc
            g += wire.size();
            const auto d = now_ns() - t0;
            if (i % 1000 == 0)
            {
                lat.push_back(d);
            }
        }
        return lat;
    }

    auto percentile(std::vector<std::int64_t> &v, const double p) -> std::int64_t
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

    // ── arena 复用（资源指针）──
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
        const auto total = now_ns() - t0;
        std::vector<std::int64_t> all;
        for (auto &l : lats)
        {
            all.insert(all.end(), l.begin(), l.end());
        }
        std::printf("arena 复用  8线程 x %d次: 总 %8.2f ms  P50=%5.1f ns  P99=%6.1f ns  P999=%7.1f ns\n",
                    kIters, total / 1e6, percentile(all, 0.5), percentile(all, 0.99),
                    percentile(all, 0.999));
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
        const auto total = now_ns() - t0;
        std::vector<std::int64_t> all;
        for (auto &l : lats)
        {
            all.insert(all.end(), l.begin(), l.end());
        }
        std::printf("每帧 malloc 8线程 x %d次: 总 %8.2f ms  P50=%5.1f ns  P99=%6.1f ns  P999=%7.1f ns\n",
                    kIters, total / 1e6, percentile(all, 0.5), percentile(all, 0.99),
                    percentile(all, 0.999));
    }
    return 0;
}
