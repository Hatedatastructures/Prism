/**
 * @file RecognitionLatency.hpp
 * @brief 有界的代次级 recognition latency 聚合
 * @details Record 与 Snapshot 只由应用控制 executor 调用。每个保留代次拥有固定直方图和近期样本环；
 *          只有 GenerationPublication 确认旧代次不再保留后，槽位才可复用。
 */
#pragma once

#include <Prism/Statistics/Snapshots.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Foundation/Utility/Diagnose/Observability.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

namespace Prism::Runtime::Detail
{
    /** @brief 真实 recognition admission 时长的固定容量聚合器。 */
    class RecognitionLatencyStore final
    {
    public:
        static constexpr std::uint64_t HistogramMaximumMicroseconds{300'000'000U};
        static constexpr std::size_t RecentSampleCapacity{256U};

        explicit RecognitionLatencyStore(
            std::shared_ptr<GenerationPublication> Publication)
            : Publication_(std::move(Publication))
        {
        }

        /** @brief 将已消费样本聚合到其精确保留代次。 */
        auto Record(const Prism::GenerationId Generation,
            const std::uint64_t DurationMicroseconds) noexcept -> bool
        {
            auto *Owner = Find(Generation);
            if (!Owner)
            {
                return false;
            }
            if (DurationMicroseconds > HistogramMaximumMicroseconds &&
                Owner->RangeExceeded != std::numeric_limits<std::uint64_t>::max())
            {
                ++Owner->RangeExceeded;
            }
            Owner->Histogram.Record(DurationMicroseconds);
            Owner->Samples.Sample(DurationMicroseconds);
            return true;
        }

        /** @brief 复制指定代次分布；代次无 owner 时返回空快照。 */
        [[nodiscard]] auto Snapshot(const Prism::GenerationId Generation) const
            -> Prism::Statistics::RecognitionLatencySnapshot
        {
            Prism::Statistics::RecognitionLatencySnapshot Result;
            Result.Generation = Generation;
            for (const auto &Owner : Owners_)
            {
                if (Owner.Generation != Generation)
                {
                    continue;
                }
                Result.SampleCount = Owner.Histogram.Count();
                Result.TracerWrittenCount = Owner.Samples.SampledCount();
                Result.TracerDroppedCount = Owner.Samples.DroppedCount();
                Result.HistogramRangeExceeded = Owner.RangeExceeded;
                Result.RecentCount = Owner.Samples.Drain(Result.RecentMicroseconds);
                if (Result.SampleCount != 0U)
                {
                    Result.P50BucketLowerBoundMicroseconds = Owner.Histogram.Percentile(50.0);
                    Result.P95BucketLowerBoundMicroseconds = Owner.Histogram.Percentile(95.0);
                    Result.P99BucketLowerBoundMicroseconds = Owner.Histogram.Percentile(99.0);
                    Result.MaximumObservedMicroseconds = Owner.Histogram.Percentile(100.0);
                }
                return Result;
            }
            return Result;
        }

    private:
        struct Owner final
        {
            Owner()
                : Histogram(HistogramMaximumMicroseconds),
                  Samples(1U, RecentSampleCapacity)
            {
            }

            auto Reset(const Prism::GenerationId Value) noexcept -> void
            {
                Histogram.Reset();
                Samples.Reset();
                RangeExceeded = 0U;
                Generation = Value;
            }

            Prism::GenerationId Generation{};
            Prism::Diagnose::HdrHistogram Histogram;
            Prism::Diagnose::SampleTracer Samples;
            std::uint64_t RangeExceeded{0U};
        };

        [[nodiscard]] auto Find(const Prism::GenerationId Generation) noexcept -> Owner *
        {
            if (!Generation)
            {
                return nullptr;
            }
            for (auto &Value : Owners_)
            {
                if (Value.Generation == Generation)
                {
                    return &Value;
                }
            }
            for (auto &Value : Owners_)
            {
                if (!Value.Generation || !Publication_ || !Publication_->Contains(Value.Generation))
                {
                    Value.Reset(Generation);
                    return &Value;
                }
            }
            return nullptr;
        }

        std::shared_ptr<GenerationPublication> Publication_;
        std::array<Owner, GenerationPublication::MaxRetainedGenerations> Owners_{};
    };
}
