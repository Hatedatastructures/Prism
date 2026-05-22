/**
 * @file gauge.hpp
 * @brief EMA 平滑瞬时值原语
 * @details 非线程安全，仅限单写者场景（如 worker 的 observe 协程）。
 * 默认 alpha=7/8，与现有延迟测量算法一致。
 */
#pragma once

namespace psm::stats
{
    /**
     * @class gauge
     * @brief EMA 平滑瞬时值
     * @details 非线程安全，仅限单写者场景。默认 alpha=7/8。
     */
    class gauge
    {
    public:
        explicit gauge(double alpha = 7.0 / 8.0) noexcept : alpha_(alpha) {}

        void update(double sample) noexcept
        {
            value_ = alpha_ * value_ + (1.0 - alpha_) * sample;
        }

        [[nodiscard]] auto value() const noexcept -> double
        {
            return value_;
        }

        void reset() noexcept
        {
            value_ = 0.0;
        }

    private:
        double value_{0.0};
        double alpha_;
    };
} // namespace psm::stats
