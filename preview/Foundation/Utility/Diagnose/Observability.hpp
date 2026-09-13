/**
 * @file Observability.hpp
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
#include <cmath>
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
            std::uint64_t V = MaxValue_;
            while (V > 0)
            {
                ++BucketCount_;
                V >>= 1;
            }
            Buckets_ = std::make_unique<std::atomic<std::uint64_t>[]>(BucketCount_);
        }

        /**
         * @brief 记录一个值
         * @param value 观测值（0..max，超限封顶）
         */
        void Record(std::uint64_t Value)
        {
            Buckets_[BucketOf(Value)].fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 记录数
         */
        [[nodiscard]] auto Count() const -> std::uint64_t
        {
            std::uint64_t Total = 0;
            for (std::size_t I = 0; I < BucketCount_; ++I)
            {
                Total += Buckets_[I].load(std::memory_order_relaxed);
            }
            return Total;
        }

        /**
         * @brief 分位数
         * @param p 百分位（0,100]
         * @return 该分位对应的值（无记录返回 0）
         */
        [[nodiscard]] auto Percentile(double Percent) const -> std::uint64_t
        {
            if (Percent <= 0 || Percent > 100)
            {
                return 0;
            }
            const auto Total = Count();
            if (Total == 0)
            {
                return 0;
            }
            const auto Target = static_cast<std::uint64_t>(static_cast<double>(Total) * Percent / 100.0);
            std::uint64_t Cumulative = 0;
            for (std::size_t I = 0; I < BucketCount_; ++I)
            {
                Cumulative += Buckets_[I].load(std::memory_order_relaxed);
                if (Cumulative > Target)
                {
                    return BucketValue(I);
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
        [[nodiscard]] auto BucketOf(std::uint64_t Value) const -> std::size_t
        {
            if (Value == 0)
            {
                return 0;
            }
            std::size_t Index = 0;
            while (Value > 0)
            {
                Value >>= 1;
                ++Index;
            }
            if (Index >= BucketCount_)
            {
                return BucketCount_ - 1;
            }
            return Index;
        }

        /**
         * @brief 桶代表值
         */
        [[nodiscard]] auto BucketValue(std::size_t Index) const -> std::uint64_t
        {
            if (Index == 0)
            {
                return 0;
            }
            return (std::uint64_t{1} << (Index - 1));
        }

        std::uint64_t MaxValue_{1};                              ///< 封顶值
        std::size_t BucketCount_{0};                             ///< 桶数
        std::unique_ptr<std::atomic<std::uint64_t>[]> Buckets_;   ///< 原子桶
    };

    /**
     * @class EwmaMeter
     * @brief 指数移动平均速率计
     * @details Mark() 只累加自上次读取以来的增量；RatePerSecond() 使用
     *          指数衰减并通过 CAS/原子标志保证多个读取者不会重复消费同一批事件。
     */
    class EwmaMeter
    {
    public:
        /// 未初始化哨兵
        static constexpr std::uint64_t Uninit = std::numeric_limits<std::uint64_t>::max();

        /**
         * @brief 构造
         * @param WindowMs 移动平均窗口（毫秒）
         */
        explicit EwmaMeter(std::uint64_t WindowMs = 1000)
            : WindowMs_(1), LastRead_(Uninit)
        {
            if (WindowMs > 0)
            {
                WindowMs_ = WindowMs;
            }
        }

        /**
         * @brief 标记 n 个事件
         */
        void Mark(std::uint64_t N)
        {
            Sum_.fetch_add(N, std::memory_order_relaxed);
        }

        /**
         * @brief 读取速率（次/秒，惰性衰减）
         * @param now 当前毫秒（可注入）
         */
        [[nodiscard]] auto RatePerSecond(std::uint64_t Now) const -> double
        {
            if (Updating_.test_and_set(std::memory_order_acquire))
            {
                return Rate_.load(std::memory_order_acquire);
            }
            const auto Release = [this]() noexcept
            {
                Updating_.clear(std::memory_order_release);
            };

            auto Last = LastRead_.load(std::memory_order_acquire);
            for (;;)
            {
                if (Last == Uninit)
                {
                    if (LastRead_.compare_exchange_weak(Last, Now, std::memory_order_acq_rel,
                                                         std::memory_order_acquire))
                    {
                        Release();
                        return 0.0;
                    }
                    continue;
                }
                if (Now <= Last)
                {
                    const auto Result = Rate_.load(std::memory_order_acquire);
                    Release();
                    return Result;
                }
                const auto Previous = Last;
                if (!LastRead_.compare_exchange_weak(Last, Now, std::memory_order_acq_rel,
                                                     std::memory_order_acquire))
                {
                    continue;
                }

                const auto Elapsed = Now - Previous;
                const auto Count = Sum_.exchange(0, std::memory_order_acq_rel);
                const auto Instant = static_cast<double>(Count) * 1000.0 /
                                     static_cast<double>(Elapsed);
                const auto PreviousRate = Rate_.load(std::memory_order_acquire);
                const auto Decay = std::exp(-static_cast<double>(Elapsed) /
                                            static_cast<double>(WindowMs_));
                const auto Weight = 1.0 - Decay;
                auto Result = PreviousRate * Decay + Instant * Weight;
                if (PreviousRate == 0.0 && Count > 0)
                {
                    Result = Instant;
                }
                Rate_.store(Result, std::memory_order_release);
                Release();
                return Result;
            }
        }

    private:
        std::uint64_t WindowMs_{1000};                    ///< 窗口（毫秒）
        mutable std::atomic<std::uint64_t> Sum_{0};       ///< 上次读取后的增量计数
        mutable std::atomic<std::uint64_t> LastRead_;     ///< 上次读取时间
        mutable std::atomic<double> Rate_{0.0};           ///< 当前 EWMA 速率
        mutable std::atomic_flag Updating_ = ATOMIC_FLAG_INIT; ///< 读取更新标志
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
        static constexpr std::size_t MaxRingSize = 1U << 16;

        /**
         * @brief 构造
         * @param Ratio 采样分母 N（≥1；1 = 全采样）
        * @param RingSize 环容量（须 2 的幂）
         */
        explicit SampleTracer(std::uint64_t Ratio = 1, std::size_t RingSize = 256)
            : Ratio_(1), RingSize_(NormalizeRingSize(RingSize)), Ring_(RingSize_)
        {
            if (Ratio < 1)
            {
                Ratio_ = 1;
            }
            else
            {
                Ratio_ = Ratio;
            }
        }

        /**
         * @brief 采样入环
         * @param value 观测值
         */
        void Sample(std::uint64_t Value)
        {
            const auto Seq = Counter_.fetch_add(1, std::memory_order_relaxed);
            if (Seq % Ratio_ != 0)
            {
                return;
            }
            const auto Slot = WriteIdx_.fetch_add(1, std::memory_order_relaxed) & (RingSize_ - 1);
            Ring_[Slot].store(Value, std::memory_order_relaxed);
            Sampled_.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 已采样数
         */
        [[nodiscard]] auto SampledCount() const -> std::uint64_t
        {
            return Sampled_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 总观测数
         */
        [[nodiscard]] auto TotalCount() const -> std::uint64_t
        {
            return Counter_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 采样率
         */
        [[nodiscard]] auto Ratio() const -> std::uint64_t
        {
            return Ratio_;
        }

        [[nodiscard]] auto Capacity() const noexcept -> std::size_t
        {
            return RingSize_;
        }

        /**
         * @brief 读回最新样本
         * @param out 输出槽
         * @return 读到的样本数（0 = 空）
         */
        [[nodiscard]] auto Drain(std::array<std::uint64_t, 8> &Output) const -> std::size_t
        {
            const auto Written = WriteIdx_.load(std::memory_order_relaxed);
            std::size_t N = 0;
            for (std::size_t I = 0; I < 8 && I < RingSize_; ++I)
            {
                const auto Index = (Written + RingSize_ - 1 - I) & (RingSize_ - 1);
                Output[N] = Ring_[Index].load(std::memory_order_relaxed);
                ++N;
            }
            return N;
        }

    private:
        static constexpr std::size_t DefaultRingSize = 256;

        [[nodiscard]] static auto NormalizeRingSize(std::size_t Size) noexcept -> std::size_t
        {
            if (Size == 0 || (Size & (Size - 1)) != 0)
            {
                return DefaultRingSize;
            }
            return (std::min)(Size, MaxRingSize);
        }

        std::uint64_t Ratio_{1};                         ///< 采样分母
        std::size_t RingSize_{DefaultRingSize};          ///< 环容量
        std::vector<std::atomic<std::uint64_t>> Ring_;   ///< 样本环
        std::atomic<std::uint64_t> Counter_{0};          ///< 观测计数
        std::atomic<std::uint64_t> WriteIdx_{0};        ///< 写索引
        std::atomic<std::uint64_t> Sampled_{0};          ///< 已采样数
    };

} // namespace Preview::Diagnose
