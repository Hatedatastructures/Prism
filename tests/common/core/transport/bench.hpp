/**
 * @file bench.hpp
 * @brief 性能基准工具（吞吐量 / 延迟统计）
 * @details 提供协议性能测试的统一测量原语：
 *          - bench_options：测试参数（总字节数 / 块大小 / 队列深度）
 *          - bench_report：结果（吞吐量 MB/s、延迟分位数）
 *          - bench_throughput()：单连接吞吐 + 延迟测量
 * @note 配合 memory_stream（内存）或真实 socket 使用。
 */

#pragma once

#include <common/core/transport/stream.hpp>

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <span>
#include <vector>

namespace psmtest
{

    /// 基准测试选项
    struct bench_options
    {
        /// 总传输字节数
        std::size_t total{64 * 1024 * 1024};
        /// 数据块大小
        std::size_t block{64 * 1024};
        /// 并发队列深度（多块并发写）
        std::size_t depth{8};
    };

    /// 基准测试报告
    struct bench_report
    {
        /// 实际传输字节数
        std::size_t bytes{0};
        /// 吞吐量（MB/s）
        double mbps{0.0};
        /// 延迟统计（单块 RTT，毫秒）
        double latency_avg{0.0};
        double latency_p50{0.0};
        double latency_p95{0.0};
        double latency_p99{0.0};
        double latency_min{0.0};
        double latency_max{0.0};
        /// 采样数
        std::size_t samples{0};
    };

    /// @brief 吞吐 + 延迟测量（单向：s 写入，r 读取）
    /// @tparam S stream concept 满足类型
    /// @param w 写入端
    /// @param r 读取端
    /// @param opt 测试选项
    /// @return 测量报告
    /// @note 延迟为写读往返时间（写 1 块 + 读回 1 块），p50/p95/p99 分位数
    template <stream S>
    auto bench_throughput(S &w, S &r, const bench_options &opt)
        -> net::awaitable<bench_report>
    {
        bench_report rep;
        const auto t0 = std::chrono::steady_clock::now();

        std::vector<std::uint8_t> block(opt.block, 0x5a);
        std::vector<std::uint8_t> echo(opt.block);
        std::vector<double> latencies;
        latencies.reserve(opt.total / opt.block);

        std::size_t sent = 0;
        while (sent < opt.total)
        {
            const auto chunk = std::min(opt.block, opt.total - sent);
            const auto t1 = std::chrono::steady_clock::now();
            const auto ec = co_await w.write_all(std::span<const std::uint8_t>(block.data(), chunk));
            if (ec)
                break;
            std::size_t got = 0;
            while (got < chunk)
            {
                const auto n = co_await r.read_some(std::span<std::uint8_t>(echo.data() + got, chunk - got));
                if (n == 0)
                    break;
                got += n;
            }
            if (got < chunk)
                break;
            const auto t2 = std::chrono::steady_clock::now();
            const double ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
            latencies.push_back(ms);
            sent += chunk;
        }

        const auto t3 = std::chrono::steady_clock::now();
        rep.bytes = sent;
        rep.samples = latencies.size();
        if (!latencies.empty())
        {
            const double sec = std::chrono::duration<double>(t3 - t0).count();
            rep.mbps = static_cast<double>(sent) / (1024.0 * 1024.0) / (sec > 0 ? sec : 1e-9);
            std::sort(latencies.begin(), latencies.end());
            const auto q = [&](double p) -> double
            {
                const auto idx = static_cast<std::size_t>(p * static_cast<double>(latencies.size() - 1));
                return latencies[idx];
            };
            rep.latency_avg = std::accumulate(latencies.begin(), latencies.end(), 0.0) /
                              static_cast<double>(latencies.size());
            rep.latency_p50 = q(0.50);
            rep.latency_p95 = q(0.95);
            rep.latency_p99 = q(0.99);
            rep.latency_min = latencies.front();
            rep.latency_max = latencies.back();
        }
        co_return rep;
    }

} // namespace psmtest
