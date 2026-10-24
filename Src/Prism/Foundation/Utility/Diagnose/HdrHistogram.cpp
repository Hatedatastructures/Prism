/**
 * @file HdrHistogram.cpp
 * @brief 指数分桶直方图实现。
 */
#include <Prism/Foundation/Utility/Diagnose/Observability.hpp>

#include <cmath>

namespace Prism::Diagnose
{
    HdrHistogram::HdrHistogram(const std::uint64_t MaxValue) : MaxValue_(1)
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

    auto HdrHistogram::Record(const std::uint64_t Value) -> void
    {
        auto Previous = ObservedMaximum_.load(std::memory_order_relaxed);
        while (Value > Previous && !ObservedMaximum_.compare_exchange_weak(Previous, Value,
                   std::memory_order_relaxed, std::memory_order_relaxed)) {}
        Buckets_[BucketOf(Value)].fetch_add(1, std::memory_order_relaxed);
    }

    auto HdrHistogram::Count() const -> std::uint64_t
    {
        std::uint64_t Total = 0;
        for (std::size_t I = 0; I < BucketCount_; ++I)
        {
            Total += Buckets_[I].load(std::memory_order_relaxed);
        }
        return Total;
    }

    auto HdrHistogram::Reset() noexcept -> void
    {
        for (std::size_t I = 0; I < BucketCount_; ++I)
        {
            Buckets_[I].store(0U, std::memory_order_relaxed);
        }
        ObservedMaximum_.store(0U, std::memory_order_relaxed);
    }

    auto HdrHistogram::Percentile(const double Percent) const -> std::uint64_t
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

    auto HdrHistogram::BucketOf(const std::uint64_t Value) const -> std::size_t
    {
        if (Value == 0)
        {
            return 0;
        }
        std::size_t Index = 0;
        auto Remaining = Value;
        while (Remaining > 0)
        {
            Remaining >>= 1;
            ++Index;
        }
        if (Index >= BucketCount_)
        {
            return BucketCount_ - 1;
        }
        return Index;
    }

    auto HdrHistogram::BucketValue(const std::size_t Index) const -> std::uint64_t
    {
        if (Index == 0)
        {
            return 0;
        }
        return (std::uint64_t{1} << (Index - 1));
    }
}
