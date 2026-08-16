/**
 * @file ObservabilityTest.cpp
 * @brief 可观测积木测试（T5-5/T5-6 O5）
 * @details 覆盖：
 *          - HDR：记录 / 分位数 / 封顶 / 空桶
 *          - EWMA：标记 / 速率 / 窗口衰减
 *          - 采样追踪：1/N 比例 / 环覆盖 / drain
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include <common/core/diagnose/observability.hpp>

namespace
{

    TEST(HdrHistogram, RecordAndCount)
    {
        psmtest::observability::hdr_histogram h(1024);
        EXPECT_EQ(h.count(), 0);

        h.record(0);
        h.record(1);
        h.record(2);
        h.record(500);
        h.record(1000);
        EXPECT_EQ(h.count(), 5);
    }

    TEST(HdrHistogram, Percentiles)
    {
        psmtest::observability::hdr_histogram h(1024);
        // 均匀分布 0..100
        for (std::uint64_t v = 0; v <= 100; ++v)
        {
            h.record(v);
        }
        // P50 约 50，P90 约 90（指数桶近似）
        EXPECT_GE(h.percentile(50), 30);
        EXPECT_LE(h.percentile(50), 64);
        EXPECT_GE(h.percentile(90), 56);
        EXPECT_LE(h.percentile(90), 128);
        EXPECT_LE(h.percentile(100), 1024);
    }

    TEST(HdrHistogram, ClampAtMax)
    {
        psmtest::observability::hdr_histogram h(16);
        h.record(999999); // 超限 → 封顶末桶
        EXPECT_EQ(h.count(), 1);
        EXPECT_EQ(h.percentile(100), 16); // 末桶代表值
    }

    TEST(HdrHistogram, EmptyPercentileZero)
    {
        psmtest::observability::hdr_histogram h(64);
        EXPECT_EQ(h.percentile(50), 0);
        EXPECT_EQ(h.percentile(0), 0);
        EXPECT_EQ(h.percentile(101), 0);
    }

    TEST(EwmaMeter, MarkAndRate)
    {
        psmtest::observability::ewma_meter meter(1000);
        EXPECT_EQ(meter.rate_per_second(0), 0.0); // 首次读取 0

        meter.mark(100);
        // 窗口 1s：1 个窗口内 100 次/窗口 → 速率 100
        EXPECT_NEAR(meter.rate_per_second(500), 200.0, 1.0); // 0.5s → 100/0.5
        EXPECT_NEAR(meter.rate_per_second(1000), 100.0, 1.0);
        EXPECT_NEAR(meter.rate_per_second(2000), 50.0, 1.0); // 2 窗口 → 衰减
    }

    TEST(SampleTracer, FullSampling)
    {
        psmtest::observability::sample_tracer tracer(1); // 全采样
        for (std::uint64_t i = 0; i < 10; ++i)
        {
            tracer.sample(i);
        }
        EXPECT_EQ(tracer.sampled_count(), 10);
        EXPECT_EQ(tracer.total_count(), 10);
    }

    TEST(SampleTracer, RatioSampling)
    {
        psmtest::observability::sample_tracer tracer(4); // 1/4
        for (std::uint64_t i = 0; i < 400; ++i)
        {
            tracer.sample(i);
        }
        EXPECT_EQ(tracer.sampled_count(), 100);
        EXPECT_EQ(tracer.total_count(), 400);
    }

    TEST(SampleTracer, RingDrain)
    {
        psmtest::observability::sample_tracer tracer(1, 16); // 小环
        for (std::uint64_t i = 0; i < 100; ++i)
        {
            tracer.sample(i);
        }
        EXPECT_EQ(tracer.sampled_count(), 100); // 覆盖最旧，计数仍准

        std::array<std::uint64_t, 8> out{};
        const auto n = tracer.drain(out);
        EXPECT_GT(n, 0);
        // 最新样本是 99
        EXPECT_EQ(out[0], 99);
    }

} // namespace
