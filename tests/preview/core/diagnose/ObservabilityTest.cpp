/**
 * @file ObservabilityTest.cpp
 * @brief 可观测积木测试（T5-5/T5-6 O5）
 * @details 覆盖：
 *          - HDR：记录 / 分位数 / 封顶 / 空桶
 *          - EWMA：标记 / 速率 / 窗口衰减
 *          - 采样追踪：1/N 比例 / 环覆盖 / Drain
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include <common/Core/Diagnose/Observability.hpp>

namespace
{

    TEST(HdrHistogram, RecordAndCount)
    {
        Preview::Diagnose::HdrHistogram h(1024);
        EXPECT_EQ(h.Count(), 0);

        h.Record(0);
        h.Record(1);
        h.Record(2);
        h.Record(500);
        h.Record(1000);
        EXPECT_EQ(h.Count(), 5);
    }

    TEST(HdrHistogram, Percentiles)
    {
        Preview::Diagnose::HdrHistogram h(1024);
        // 均匀分布 0..100
        for (std::uint64_t v = 0; v <= 100; ++v)
        {
            h.Record(v);
        }
        // P50 约 50，P90 约 90（指数桶近似）
        EXPECT_GE(h.Percentile(50), 30);
        EXPECT_LE(h.Percentile(50), 64);
        EXPECT_GE(h.Percentile(90), 56);
        EXPECT_LE(h.Percentile(90), 128);
        EXPECT_LE(h.Percentile(100), 1024);
    }

    TEST(HdrHistogram, ClampAtMax)
    {
        Preview::Diagnose::HdrHistogram h(16);
        h.Record(999999); // 超限 → 封顶末桶
        EXPECT_EQ(h.Count(), 1);
        EXPECT_EQ(h.Percentile(100), 16); // 末桶代表值
    }

    TEST(HdrHistogram, EmptyPercentileZero)
    {
        Preview::Diagnose::HdrHistogram h(64);
        EXPECT_EQ(h.Percentile(50), 0);
        EXPECT_EQ(h.Percentile(0), 0);
        EXPECT_EQ(h.Percentile(101), 0);
    }

    TEST(EwmaMeter, MarkAndRate)
    {
        Preview::Diagnose::EwmaMeter meter(1000);
        EXPECT_EQ(meter.RatePerSecond(0), 0.0); // 首次读取 0

        meter.Mark(100);
        // 窗口 1s：1 个窗口内 100 次/窗口 → 速率 100
        EXPECT_NEAR(meter.RatePerSecond(500), 200.0, 1.0); // 0.5s → 100/0.5
        EXPECT_NEAR(meter.RatePerSecond(1000), 100.0, 1.0);
        EXPECT_NEAR(meter.RatePerSecond(2000), 50.0, 1.0); // 2 窗口 → 衰减
    }

    TEST(SampleTracer, FullSampling)
    {
        Preview::Diagnose::SampleTracer tracer(1); // 全采样
        for (std::uint64_t i = 0; i < 10; ++i)
        {
            tracer.Sample(i);
        }
        EXPECT_EQ(tracer.SampledCount(), 10);
        EXPECT_EQ(tracer.TotalCount(), 10);
    }

    TEST(SampleTracer, RatioSampling)
    {
        Preview::Diagnose::SampleTracer tracer(4); // 1/4
        for (std::uint64_t i = 0; i < 400; ++i)
        {
            tracer.Sample(i);
        }
        EXPECT_EQ(tracer.SampledCount(), 100);
        EXPECT_EQ(tracer.TotalCount(), 400);
    }

    TEST(SampleTracer, RingDrain)
    {
        Preview::Diagnose::SampleTracer tracer(1, 16); // 小环
        for (std::uint64_t i = 0; i < 100; ++i)
        {
            tracer.Sample(i);
        }
        EXPECT_EQ(tracer.SampledCount(), 100); // 覆盖最旧，计数仍准

        std::array<std::uint64_t, 8> out{};
        const auto n = tracer.Drain(out);
        EXPECT_GT(n, 0);
        // 最新样本是 99
        EXPECT_EQ(out[0], 99);
    }

} // namespace
