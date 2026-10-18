/**
 * @file Observability.hpp
 * @brief 提供直方图、事件速率计和有界采样环。
 * @details 这些类型以原子计数记录观测值，不负责日志格式化或 sink 写入。
 */

#pragma once

#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

namespace Prism::Diagnose
{

    /**
     * @brief 使用指数分桶记录数值分布。
     * @details 每个桶代表一个按 2 的幂次划分的数值范围。超过配置上限的值计入末桶；
     *          查询分位数时返回对应桶的代表值，而不是原始观测值。
     */
    class HdrHistogram
    {
    public:
        /**
         * @brief 创建直方图并按上限分配原子计数桶。
         * @param MaxValue 观测值上限。传入 0 时使用 1；更大的观测值归入末桶。
         */
        explicit HdrHistogram(std::uint64_t MaxValue) : MaxValue_(1)
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
         * @brief 将一次观测计入对应桶。
         * @param Value 观测值；大于配置上限的值归入末桶。
         */
        void Record(std::uint64_t Value)
        {
            auto Previous = ObservedMaximum_.load(std::memory_order_relaxed);
            while (Value > Previous && !ObservedMaximum_.compare_exchange_weak(Previous, Value,
                       std::memory_order_relaxed, std::memory_order_relaxed)) {}
            Buckets_[BucketOf(Value)].fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 返回所有桶中当前记录数之和。
         * @details 各桶使用独立的原子读取；并发记录时，结果不是同一时刻的事务性快照。
         * @return 当前可见的观测总数。
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

        /** @brief 仅在 owner 确认没有并发 Record 后清空本代分布。 */
        auto Reset() noexcept -> void
        {
            for (std::size_t I = 0; I < BucketCount_; ++I)
            {
                Buckets_[I].store(0U, std::memory_order_relaxed);
            }
            ObservedMaximum_.store(0U, std::memory_order_relaxed);
        }

        /**
         * @brief 查询指定百分位所在桶的代表值。
         * @param Percent 百分位，范围为 (0, 100]；范围外的值返回 0。
         * @return nearest-rank所在桶的下边界（近似），P100返回真实观察最大值；无记录返回0。
         */
        [[nodiscard]] auto Percentile(double Percent) const -> std::uint64_t
        {
            if (!std::isfinite(Percent) || Percent <= 0 || Percent > 100)
            {
                return 0;
            }
            const auto Total = Count();
            if (Total == 0)
            {
                return 0;
            }
            if (Percent == 100) return ObservedMaximum_.load(std::memory_order_relaxed);
            const auto Rank = std::ceil(static_cast<long double>(Total) *
                                       static_cast<long double>(Percent) / 100.0L);
            auto Target = Total;
            if (Rank < static_cast<long double>(Total)) Target = static_cast<std::uint64_t>(Rank);
            if (Target == 0) Target = 1;
            std::uint64_t Cumulative = 0;
            for (std::size_t I = 0; I < BucketCount_; ++I)
            {
                Cumulative += Buckets_[I].load(std::memory_order_relaxed);
                if (Cumulative >= Target)
                {
                    return BucketValue(I);
                }
            }
            return ObservedMaximum_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 返回构造时采用的观测上限。
         * @return 超出此值的观测所归入的上限值。
         */
        [[nodiscard]] auto MaxValue() const -> std::uint64_t
        {
            return MaxValue_;
        }

    private:
        /**
         * @brief 根据数值的二进制位宽计算桶索引，并将超出范围的索引封顶。
         * @param Value 待映射的观测值。
         * @return 有效桶索引。
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
         * @brief 返回桶索引对应的指数分桶代表值。
         * @param Index 桶索引。
         * @return 索引 0 对应 0；其他索引对应相应的 2 的幂次。
         */
        [[nodiscard]] auto BucketValue(std::size_t Index) const -> std::uint64_t
        {
            if (Index == 0)
            {
                return 0;
            }
            return (std::uint64_t{1} << (Index - 1));
        }

        std::uint64_t MaxValue_{1}; ///< 封顶值
        std::atomic<std::uint64_t> ObservedMaximum_{0}; ///< 真实观察最大值，不以配置上限替代样本。
        std::size_t BucketCount_{0}; ///< 桶数
        std::unique_ptr<std::atomic<std::uint64_t>[]> Buckets_; ///< 原子桶
    };

    /**
     * @brief 以指数加权移动平均估算事件速率。
     * @details Mark() 累加待计算的事件数；RatePerSecond() 在读取时消费这段时间的增量，
     *          并按配置窗口平滑瞬时速率。并发读取由原子标志串行化，Mark() 可并发调用。
     */
    class EwmaMeter
    {
    public:
        /// 表示尚未记录首次读取时间的哨兵值。
        static constexpr std::uint64_t Uninit = std::numeric_limits<std::uint64_t>::max();

        /**
         * @brief 创建速率计。
         * @param WindowMs 指数衰减窗口，单位为毫秒；传入 0 时使用 1 毫秒。
         */
        explicit EwmaMeter(std::uint64_t WindowMs = 1000) : WindowMs_(1), LastRead_(Uninit)
        {
            if (WindowMs > 0)
            {
                WindowMs_ = WindowMs;
            }
        }

        /**
         * @brief 累加尚未参与速率计算的事件数。
         * @param N 本次增加的事件数。
         */
        void Mark(std::uint64_t N)
        {
            Sum_.fetch_add(N, std::memory_order_relaxed);
        }

        /**
         * @brief 使用给定时间点更新并返回平滑后的事件速率。
         * @param Now 当前时间点的毫秒数；连续调用应使用同一时钟和时间基准。
         * @return 每秒事件数。首次调用仅建立时间基准并返回 0；时间未前进时返回上次速率。
         * @note 若另一个读取者正在更新，本次调用直接返回最近一次已发布的速率。
         */
        [[nodiscard]] auto RatePerSecond(std::uint64_t Now) const -> double
        {
            if (Updating_.test_and_set(std::memory_order_acquire))
            {
                return Rate_.load(std::memory_order_acquire);
            }
            const auto Release = [this]() noexcept { Updating_.clear(std::memory_order_release); };

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
                const auto Instant = static_cast<double>(Count) * 1000.0 / static_cast<double>(Elapsed);
                const auto PreviousRate = Rate_.load(std::memory_order_acquire);
                const auto Decay = std::exp(-static_cast<double>(Elapsed) / static_cast<double>(WindowMs_));
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
        std::uint64_t WindowMs_{1000}; ///< 窗口（毫秒）
        mutable std::atomic<std::uint64_t> Sum_{0}; ///< 上次读取后的增量计数
        mutable std::atomic<std::uint64_t> LastRead_; ///< 上次读取时间
        mutable std::atomic<double> Rate_{0.0}; ///< 当前 EWMA 速率
        mutable std::atomic_flag Updating_ = ATOMIC_FLAG_INIT; ///< 读取更新标志
    };

    /**
     * @brief 按固定比例抽样，并在有界环中保留近期样本。
     * @details 每次观测都会推进计数器，序号能被采样分母整除时才写入环；环满后新样本覆盖旧槽位。
     *          计数和样本槽使用原子操作，便于与并发观测线程共同使用。
     */
    class SampleTracer
    {
        struct SampleSlot final
        {
            std::atomic_flag Editing = ATOMIC_FLAG_INIT;
            std::atomic<std::uint64_t> Sequence{0};
            std::atomic<std::uint64_t> Value{0};
        };
    public:
        static constexpr std::size_t MaxRingSize = 1U << 16; ///< 采样环允许的最大容量。

        /**
         * @brief 创建采样器并分配固定容量的原子样本环。
         * @param Ratio 采样分母；1 表示每次观测都采样。
         * @param RingSize 请求的环容量。必须是 2 的幂；否则使用默认容量，超出上限时封顶。
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
         * @brief 记录一次观测，并在命中采样比例时写入环。
         * @param Value 本次观测值。
         * @note 环空间耗尽后会覆盖最早的样本；采样计数仍持续累计。
         */
        void Sample(std::uint64_t Value)
        {
            const auto Seq = Counter_.fetch_add(1, std::memory_order_relaxed);
            if (Seq % Ratio_ != 0)
            {
                return;
            }
            const auto Ticket = ReserveTicket();
            if (!Ticket) { Dropped_.fetch_add(1, std::memory_order_relaxed); return; }
            auto& Slot = Ring_[*Ticket & (RingSize_ - 1)];
            if (Slot.Editing.test_and_set(std::memory_order_acquire))
            { Dropped_.fetch_add(1, std::memory_order_relaxed); return; }
            Slot.Sequence.store(0, std::memory_order_release);
            Slot.Value.store(Value, std::memory_order_release);
            Slot.Sequence.store(*Ticket + 1, std::memory_order_release);
            Slot.Editing.clear(std::memory_order_release);
            Sampled_.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 返回采样器生命周期内写入环的样本总数。
         * @return 命中采样比例的观测次数，不受环槽位覆盖影响。
         */
        [[nodiscard]] auto SampledCount() const -> std::uint64_t
        {
            return Sampled_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 返回采样器生命周期内收到的观测总数。
         * @return 调用 Sample() 的累计次数。
         */
        [[nodiscard]] auto TotalCount() const -> std::uint64_t
        {
            return Counter_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 返回当前采样分母。
         * @return 每 N 次观测采样一次时的 N；1 表示全采样。
         */
        [[nodiscard]] auto Ratio() const -> std::uint64_t
        {
            return Ratio_;
        }

        /**
         * @brief 返回样本环容量。
         * @return 可保存的原子样本槽位数。
         */
        [[nodiscard]] auto Capacity() const noexcept -> std::size_t
        {
            return RingSize_;
        }

        /**
         * @brief 按从新到旧的顺序复制最多8个实际已发布样本。
         * @param Output 接收样本值的固定长度数组。
         * @return 实际写入数量；未发布或被并发改写的槽跳过，不用默认零值虚构样本。
         * @note 并发读取是有界近似快照；合法零样本仍有非零发布序号。
         */
        [[nodiscard]] auto Drain(std::array<std::uint64_t, 8>& Output) const -> std::size_t
        {
            const auto Written = WriteIdx_.load(std::memory_order_relaxed);
            std::size_t N = 0;
            for (std::size_t I = 0; N < Output.size() && I < RingSize_ && I < Written; ++I)
            {
                const auto Expected = Written - I;
                const auto& Slot = Ring_[(Expected - 1) & (RingSize_ - 1)];
                const auto Before = Slot.Sequence.load(std::memory_order_acquire);
                if (Before != Expected) continue;
                const auto Value = Slot.Value.load(std::memory_order_acquire);
                if (Slot.Sequence.load(std::memory_order_acquire) != Before) continue;
                Output[N] = Value;
                ++N;
            }
            return N;
        }

        /** @brief 仅在所属聚合 executor 没有并发 Sample/Drain 时重置代次样本环。 */
        auto Reset() noexcept -> void
        {
            Counter_.store(0U, std::memory_order_relaxed);
            Sampled_.store(0U, std::memory_order_relaxed);
            WriteIdx_.store(0U, std::memory_order_relaxed);
            Dropped_.store(0U, std::memory_order_relaxed);
            for (std::size_t Index = 0; Index < RingSize_; ++Index)
            {
                Ring_[Index].Sequence.store(0U, std::memory_order_relaxed);
                Ring_[Index].Value.store(0U, std::memory_order_relaxed);
                Ring_[Index].Editing.clear(std::memory_order_release);
            }
        }

        /** @brief 原子门闩竞争或序号耗尽导致的真实观察丢弃，与业务错误分离。 */
        [[nodiscard]] auto DroppedCount() const noexcept -> std::uint64_t
        { return Dropped_.load(std::memory_order_relaxed); }

    private:
        static constexpr std::size_t DefaultRingSize = 256; ///< 容量参数无效时采用的默认槽位数。

        /** @brief 有限CAS预约单调采样序号；耗尽不回绕，竞争不足直接计观察丢弃。 */
        [[nodiscard]] auto ReserveTicket() noexcept -> std::optional<std::uint64_t>
        {
            auto Current = WriteIdx_.load(std::memory_order_relaxed);
            for (unsigned Attempt = 0; Attempt < 4 && Current != UINT64_MAX; ++Attempt)
                if (WriteIdx_.compare_exchange_strong(Current, Current + 1, std::memory_order_relaxed))
                    return Current;
            return std::nullopt;
        }

        /**
         * @brief 将请求的容量规范化为支持按位取模的 2 的幂。
         * @param Size 请求的环容量。
         * @return 非零且为 2 的幂时返回不超过 MaxRingSize 的容量；其他值返回默认容量。
         */
        [[nodiscard]] static auto NormalizeRingSize(std::size_t Size) noexcept -> std::size_t
        {
            if (Size == 0 || (Size & (Size - 1)) != 0)
            {
                return DefaultRingSize;
            }
            return (std::min)(Size, MaxRingSize);
        }

        std::uint64_t Ratio_{1}; ///< 采样分母
        std::size_t RingSize_{DefaultRingSize}; ///< 环容量
        std::vector<SampleSlot> Ring_; ///< 带发布序号的有界样本环。
        std::atomic<std::uint64_t> Counter_{0}; ///< 观测计数
        std::atomic<std::uint64_t> WriteIdx_{0}; ///< 写索引
        std::atomic<std::uint64_t> Sampled_{0}; ///< 已采样数
        std::atomic<std::uint64_t> Dropped_{0}; ///< 未形成真实样本的观察失败。
    };

} // namespace Prism::Diagnose
