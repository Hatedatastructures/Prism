/**
 * @file bench.hpp
 * @brief 性能基准工具（吞吐量 / 延迟统计）
 * @details 提供协议性能测试的统一测量原语：
 *          - bench_options：测试参数（总字节数 / 块大小 / 队列深度）
 *          - bench_report：结果（吞吐量 MB/s、延迟分位数）
 *          - bench_throughput() / bench_throughput_tx()：单连接吞吐 + 延迟测量
 * @note 配合 memory_stream（内存）或真实 socket 使用。
 * @note 测量循环与分位数统计统一在 detail::run_bench，旧（read_some/write_all）
 *       与新（async_read_some/async_write_some）接口差异由薄包装收敛。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <span>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/transport/stream.hpp>

namespace preview
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

    /// 旧接口传输概念（read_some/write_all，供 bench 消费）
    /// @tparam T 传输类型（协议 session / memory_stream 均满足）
    template <typename T>
    concept bench_stream = requires(T &s, std::span<std::uint8_t> buf, std::span<const std::uint8_t> wbuf) {
        { s.read_some(buf) } -> std::same_as<net::awaitable<std::size_t>>;
        { s.write_all(wbuf) } -> std::same_as<net::awaitable<boost::system::error_code>>;
    };

    /// 新接口传输概念（async_read_some/async_write_some，供 bench 消费）
    /// @tparam T 传输类型（协议 server/client / memory_stream 均满足）
    template <typename T>
    concept bench_tx =
        requires(T &s, std::span<std::byte> buf, std::span<const std::byte> wbuf, std::error_code &ec) {
            { s.async_read_some(buf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            { s.async_write_some(wbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
        };

    namespace detail
    {

        /**
         * @brief 吞吐与延迟测量公共实现
         * @tparam WriteBlock 写一块回调：返回 true = 写满成功
         * @tparam ReadBlock 读一块回调：返回实际读回字节数（< 块长 = 提前结束）
         * @param write_block 写块协程
         * @param read_block 读块协程
         * @param opt 测试选项
         * @return 测量报告
         * @details 循环执行「写一块 + 读回一块」直至完成、写失败或读不足，
         *          记录每块往返延迟。p50/p95/p99 分位数经排序取插值。
         */
        template <typename WriteBlock, typename ReadBlock>
        auto run_bench(WriteBlock write_block, ReadBlock read_block, const bench_options &opt)
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
                const bool wok = co_await write_block(std::span<const std::uint8_t>(block.data(), chunk));
                if (!wok)
                {
                    break;
                }
                const auto got = co_await read_block(std::span<std::uint8_t>(echo.data(), chunk));
                if (got < chunk)
                {
                    break;
                }
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
                if (sec > 0)
                {
                    rep.mbps = static_cast<double>(sent) / (1024.0 * 1024.0) / sec;
                }
                else
                {
                    rep.mbps = static_cast<double>(sent) / (1024.0 * 1024.0) / 1e-9;
                }
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

    } // namespace detail

    /**
     * @brief 吞吐 + 延迟测量（旧接口版本：read_some/write_all）
     * @tparam S bench_stream 满足类型
     * @param w 写入端
     * @param r 读取端
     * @param opt 测试选项
     * @return 测量报告
     * @note 延迟为写读往返时间（写 1 块 + 读回 1 块），p50/p95/p99 分位数
     */
    template <bench_stream S>
    auto bench_throughput(S &w, S &r, const bench_options &opt) -> net::awaitable<bench_report>
    {
        return detail::run_bench(
            [&w](std::span<const std::uint8_t> data) -> net::awaitable<bool>
            {
                const auto ec = co_await w.write_all(data);
                co_return !ec;
            },
            [&r](std::span<std::uint8_t> data) -> net::awaitable<std::size_t>
            {
                std::size_t got = 0;
                while (got < data.size())
                {
                    const auto n = co_await r.read_some(data.subspan(got));
                    if (n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                co_return got;
            },
            opt);
    }

    /**
     * @brief 吞吐 + 延迟测量（transmission 接口版本）
     * @tparam S bench_tx 满足类型（transmission 装饰器链）
     * @param w 写入端
     * @param r 读取端
     * @param opt 测试选项
     * @return 测量报告
     * @details 与 bench_throughput 语义一致，面向新接口协议会话
     * （server/client 分离设计）。
     */
    template <bench_tx S>
    auto bench_throughput_tx(S &w, S &r, const bench_options &opt) -> net::awaitable<bench_report>
    {
        return detail::run_bench(
            [&w](std::span<const std::uint8_t> data) -> net::awaitable<bool>
            {
                std::size_t done = 0;
                while (done < data.size())
                {
                    std::error_code ec;
                    const auto n = co_await w.async_write_some(
                        as_bytes(std::span<const std::uint8_t>(data.data() + done, data.size() - done)), ec);
                    if (ec || n == 0)
                    {
                        co_return false;
                    }
                    done += n;
                }
                co_return true;
            },
            [&r](std::span<std::uint8_t> data) -> net::awaitable<std::size_t>
            {
                std::size_t got = 0;
                while (got < data.size())
                {
                    std::error_code ec;
                    const auto n = co_await r.async_read_some(as_bytes(data.subspan(got)), ec);
                    if (ec || n == 0)
                    {
                        break;
                    }
                    got += n;
                }
                co_return got;
            },
            opt);
    }

} // namespace preview