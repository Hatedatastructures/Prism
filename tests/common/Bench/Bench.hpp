/**
 * @file bench.hpp
 * @brief 性能基准工具（吞吐量 / 延迟统计）
 * @details 提供协议性能测试的统一测量原语：
 *          - BenchOptions：测试参数（总字节数 / 块大小 / 队列深度）
 *          - BenchReport：结果（吞吐量 MB/s、延迟分位数）
 *          - BenchThroughput() / BenchThroughputTx()：单连接吞吐 + 延迟测量
 * @note 配合 MemoryStream（内存）或真实 socket 使用。
 * @note 测量循环与分位数统计统一在 detail::RunBench，旧（ReadSome/WriteAll）
 *       与新（AsyncReadSome/AsyncWriteSome）接口差异由薄包装收敛。
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

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Transport/Stream.hpp>

namespace Preview
{

    /// 基准测试选项
    struct BenchOptions
    {
        /// 总传输字节数
        std::size_t Total{64 * 1024 * 1024};
        /// 数据块大小
        std::size_t block{64 * 1024};
        /// 并发队列深度（多块并发写）
        std::size_t depth{8};
    };

    /// 基准测试报告
    struct BenchReport
    {
        /// 实际传输字节数
        std::size_t Bytes{0};
        /// 吞吐量（MB/s）
        double mbps{0.0};
        /// 延迟统计（单块 RTT，毫秒）
        double LatencyAvg{0.0};
        double LatencyP50{0.0};
        double LatencyP95{0.0};
        double LatencyP99{0.0};
        double LatencyMin{0.0};
        double LatencyMax{0.0};
        /// 采样数
        std::size_t samples{0};
    };

    /// 旧接口传输概念（ReadSome/WriteAll，供 bench 消费）
    /// @tparam T 传输类型（协议 Session / MemoryStream 均满足）
    template <typename T>
    concept BenchStream = requires(T &s, std::span<std::uint8_t> buf, std::span<const std::uint8_t> wbuf) {
        { s.ReadSome(buf) } -> std::same_as<net::awaitable<std::size_t>>;
        { s.WriteAll(wbuf) } -> std::same_as<net::awaitable<boost::system::error_code>>;
    };

    /// 新接口传输概念（AsyncReadSome/AsyncWriteSome，供 bench 消费）
    /// @tparam T 传输类型（协议 Server/Client / MemoryStream 均满足）
    template <typename T>
    concept BenchTx =
        requires(T &s, std::span<std::byte> buf, std::span<const std::byte> wbuf, std::error_code &ec) {
            { s.AsyncReadSome(buf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            { s.AsyncWriteSome(wbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
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
        auto RunBench(WriteBlock write_block, ReadBlock read_block, const BenchOptions &opt)
            -> net::awaitable<BenchReport>
        {
            BenchReport rep;
            const auto t0 = std::chrono::steady_clock::now();

            std::vector<std::uint8_t> block(opt.block, 0x5a);
            std::vector<std::uint8_t> echo(opt.block);
            std::vector<double> latencies;
            latencies.reserve(opt.Total / opt.block);

            std::size_t sent = 0;
            while (sent < opt.Total)
            {
                const auto chunk = std::min(opt.block, opt.Total - sent);
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
            rep.Bytes = sent;
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
                rep.LatencyAvg = std::accumulate(latencies.begin(), latencies.end(), 0.0) /
                                  static_cast<double>(latencies.size());
                rep.LatencyP50 = q(0.50);
                rep.LatencyP95 = q(0.95);
                rep.LatencyP99 = q(0.99);
                rep.LatencyMin = latencies.front();
                rep.LatencyMax = latencies.back();
            }
            co_return rep;
        }

    } // namespace detail

    /**
     * @brief 吞吐 + 延迟测量（旧接口版本：ReadSome/WriteAll）
     * @tparam S BenchStream 满足类型
     * @param w 写入端
     * @param r 读取端
     * @param opt 测试选项
     * @return 测量报告
     * @note 延迟为写读往返时间（写 1 块 + 读回 1 块），p50/p95/p99 分位数
     */
    template <BenchStream S>
    auto BenchThroughput(S &w, S &r, const BenchOptions &opt) -> net::awaitable<BenchReport>
    {
        return detail::RunBench(
            [&w](std::span<const std::uint8_t> Data) -> net::awaitable<bool>
            {
                const auto ec = co_await w.WriteAll(Data);
                co_return !ec;
            },
            [&r](std::span<std::uint8_t> Data) -> net::awaitable<std::size_t>
            {
                std::size_t got = 0;
                while (got < Data.size())
                {
                    const auto n = co_await r.ReadSome(Data.subspan(got));
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
     * @brief 吞吐 + 延迟测量（Transmission 接口版本）
     * @tparam S BenchTx 满足类型（Transmission 装饰器链）
     * @param w 写入端
     * @param r 读取端
     * @param opt 测试选项
     * @return 测量报告
     * @details 与 BenchThroughput 语义一致，面向新接口协议会话
     * （Server/Client 分离设计）。
     */
    template <BenchTx S>
    auto BenchThroughputTx(S &w, S &r, const BenchOptions &opt) -> net::awaitable<BenchReport>
    {
        return detail::RunBench(
            [&w](std::span<const std::uint8_t> Data) -> net::awaitable<bool>
            {
                std::size_t Done = 0;
                while (Done < Data.size())
                {
                    std::error_code ec;
                    const auto n = co_await w.AsyncWriteSome(
                        AsBytes(std::span<const std::uint8_t>(Data.data() + Done, Data.size() - Done)), ec);
                    if (ec || n == 0)
                    {
                        co_return false;
                    }
                    Done += n;
                }
                co_return true;
            },
            [&r](std::span<std::uint8_t> Data) -> net::awaitable<std::size_t>
            {
                std::size_t got = 0;
                while (got < Data.size())
                {
                    std::error_code ec;
                    const auto n = co_await r.AsyncReadSome(AsBytes(Data.subspan(got)), ec);
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

} // namespace Preview