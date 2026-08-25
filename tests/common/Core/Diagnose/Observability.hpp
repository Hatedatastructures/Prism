/**
 * @file observability.hpp
 * @brief 可观测积木（T5-5 O5 接口 + T5-6 实现）
 * @details 三个核心组件：
 *          - HdrHistogram：指数 bucket 直方图（记录 + 分位数）
 *          - EwmaMeter：指数移动平均速率计（Mark + rate）
 *          - SampleTracer：1/N 采样追踪（原子 + SPSC ring）
 * @note 接口与实现合一（测试库自包含）；生产可观测模块可替换
 */

#pragma once

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

namespace Preview::Diagnose
{

    /**
     * @class HdrHistogram
     * @brief 高动态范围直方图
     * @details 指数 bucket（2^k 边界，约 log2(max) 个桶）：
     *          - Record：原子递增对应桶
     *          - Percentile：遍历累积求分位数
     *          - 超 max 封顶到末桶
     */
    class HdrHistogram
    {
    public:
        /**
         * @brief 构造
         * @param MaxValue 最大可记录值（封顶）
         */
        explicit HdrHistogram(std::uint64_t MaxValue)
            : MaxValue_(1)
        {
            if (MaxValue > 0)
            {
                MaxValue_ = MaxValue;
            }
            // bucket 数 = log2(MaxValue) + 1（0 值也占一桶）
            std::uint64_t v = MaxValue_;
            while (v > 0)
            {
                ++BucketCount_;
                v >>= 1;
            }
            buckets_ = std::make_unique<std::atomic<std::uint64_t>[]>(BucketCount_);
        }

        /**
         * @brief 记录一个值
         * @param value 观测值（0..max，超限封顶）
         */
        void Record(std::uint64_t value)
        {
            buckets_[BucketOf(value)].fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 记录数
         */
        [[nodiscard]] auto Count() const -> std::uint64_t
        {
            std::uint64_t Total = 0;
            for (std::size_t i = 0; i < BucketCount_; ++i)
            {
                Total += buckets_[i].load(std::memory_order_relaxed);
            }
            return Total;
        }

        /**
         * @brief 分位数
         * @param p 百分位（0,100]
         * @return 该分位对应的值（无记录返回 0）
         */
        [[nodiscard]] auto Percentile(double p) const -> std::uint64_t
        {
            if (p <= 0 || p > 100)
            {
                return 0;
            }
            const auto Total = Count();
            if (Total == 0)
            {
                return 0;
            }
            const auto Target = static_cast<std::uint64_t>(static_cast<double>(Total) * p / 100.0);
            std::uint64_t cumulative = 0;
            for (std::size_t i = 0; i < BucketCount_; ++i)
            {
                cumulative += buckets_[i].load(std::memory_order_relaxed);
                if (cumulative > Target)
                {
                    return BucketValue(i);
                }
            }
            return MaxValue_;
        }

        /**
         * @brief 最大值（封顶）
         */
        [[nodiscard]] auto MaxValue() const -> std::uint64_t
        {
            return MaxValue_;
        }

    private:
        /**
         * @brief 值的桶索引（指数分桶）
         */
        [[nodiscard]] auto BucketOf(std::uint64_t value) const -> std::size_t
        {
            if (value == 0)
            {
                return 0;
            }
            std::size_t idx = 0;
            while (value > 0)
            {
                value >>= 1;
                ++idx;
            }
            if (idx >= BucketCount_)
            {
                return BucketCount_ - 1;
            }
            return idx;
        }

        /**
         * @brief 桶代表值
         */
        [[nodiscard]] auto BucketValue(std::size_t idx) const -> std::uint64_t
        {
            if (idx == 0)
            {
                return 0;
            }
            return (std::uint64_t{1} << (idx - 1));
        }

        std::uint64_t MaxValue_{1};                              ///< 封顶值
        std::size_t BucketCount_{0};                             ///< 桶数
        std::unique_ptr<std::atomic<std::uint64_t>[]> buckets_;   ///< 原子桶
    };

    /**
     * @class EwmaMeter
     * @brief 指数移动平均速率计
     * @details 原子累加未衰减计数 + 惰性衰减计算：
     *          rate = sum / window，按经过间隔指数衰减。
     *          单线程读场景（采样低频）足够准确。
     */
    class EwmaMeter
    {
    public:
        /// 未初始化哨兵
        static constexpr std::uint64_t uninit = std::numeric_limits<std::uint64_t>::max();

        /**
         * @brief 构造
         * @param WindowMs 移动平均窗口（毫秒）
         */
        explicit EwmaMeter(std::uint64_t WindowMs = 1000)
            : WindowMs_(1), LastRead_(uninit)
        {
            if (WindowMs > 0)
            {
                WindowMs_ = WindowMs;
            }
        }

        /**
         * @brief 标记 n 个事件
         */
        void Mark(std::uint64_t n)
        {
            sum_.fetch_add(n, std::memory_order_relaxed);
        }

        /**
         * @brief 读取速率（次/秒，惰性衰减）
         * @param now 当前毫秒（可注入）
         */
        [[nodiscard]] auto RatePerSecond(std::uint64_t now) const -> double
        {
            auto last = LastRead_.load(std::memory_order_relaxed);
            if (last == uninit)
            {
                LastRead_.store(now, std::memory_order_relaxed);
                return 0.0;
            }
            const auto sum = sum_.load(std::memory_order_relaxed);
            std::uint64_t elapsed = 1;
            if (now > last)
            {
                elapsed = now - last;
            }
            // 衰减因子：经过窗口数越多，速率越接近平均
            const auto windows = static_cast<double>(elapsed) / static_cast<double>(WindowMs_);
            return static_cast<double>(sum) / windows;
        }

    private:
        std::uint64_t WindowMs_{1000};                    ///< 窗口（毫秒）
        mutable std::atomic<std::uint64_t> sum_{0};        ///< 未衰减计数
        mutable std::atomic<std::uint64_t> LastRead_;     ///< 上次读取
    };

    /**
     * @class SampleTracer
     * @brief 1/N 采样追踪
     * @details 原子计数选择器 + SPSC ring：
     *          - Sample：计数器 % N == 0 才入环（1/N 采样）
     *          - Drain：读回样本（并发安全，覆盖最旧）
     */
    class SampleTracer
    {
    public:
        /**
         * @brief 构造
         * @param Ratio 采样分母 N（≥1；1 = 全采样）
         * @param RingSize 环容量（须 2 的幂）
         */
        explicit SampleTracer(std::uint64_t Ratio = 1, std::size_t RingSize = 256)
            : ratio_(1), RingSize_(RingSize), ring_(RingSize)
        {
            if (Ratio < 1)
            {
                ratio_ = 1;
            }
            else
            {
                ratio_ = Ratio;
            }
        }

        /**
         * @brief 采样入环
         * @param value 观测值
         */
        void Sample(std::uint64_t value)
        {
            const auto seq = counter_.fetch_add(1, std::memory_order_relaxed);
            if (seq % ratio_ != 0)
            {
                return;
            }
            const auto Slot = WriteIdx_.fetch_add(1, std::memory_order_relaxed) & (RingSize_ - 1);
            ring_[Slot].store(value, std::memory_order_relaxed);
            sampled_.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 已采样数
         */
        [[nodiscard]] auto SampledCount() const -> std::uint64_t
        {
            return sampled_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 总观测数
         */
        [[nodiscard]] auto TotalCount() const -> std::uint64_t
        {
            return counter_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 采样率
         */
        [[nodiscard]] auto Ratio() const -> std::uint64_t
        {
            return ratio_;
        }

        /**
         * @brief 读回最新样本
         * @param out 输出槽
         * @return 读到的样本数（0 = 空）
         */
        [[nodiscard]] auto Drain(std::array<std::uint64_t, 8> &out) const -> std::size_t
        {
            const auto written = WriteIdx_.load(std::memory_order_relaxed);
            std::size_t n = 0;
            for (std::size_t i = 0; i < 8 && i < RingSize_; ++i)
            {
                const auto idx = (written + RingSize_ - 1 - i) & (RingSize_ - 1);
                out[n] = ring_[idx].load(std::memory_order_relaxed);
                ++n;
            }
            return n;
        }

    private:
        std::uint64_t ratio_{1};                         ///< 采样分母
        std::size_t RingSize_{256};                     ///< 环容量
        std::vector<std::atomic<std::uint64_t>> ring_;   ///< 样本环
        std::atomic<std::uint64_t> counter_{0};          ///< 观测计数
        std::atomic<std::uint64_t> WriteIdx_{0};        ///< 写索引
        std::atomic<std::uint64_t> sampled_{0};          ///< 已采样数
    };

} // namespace Preview::Diagnose
