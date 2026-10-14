/**
 * @file RecognitionLatencyScope.hpp
 * @brief Session recognition admission 的异常安全计时作用域
 * @details Scope 只在 sink 已安装时读取时钟。析构仅报告数值样本且不抛出，
 *          不捕获或转换 admission 异常；失败码与 Native cause 仍由 Session owner 处理。
 */
#pragma once

#include <Preview/Foundation/Utility/TrafficSink.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>

namespace Preview::Runtime::Detail
{
    /**
     * @brief 以 Session 当前真实身份报告一次 admission 耗时。
     * @details Scope 独占 sink 的共享引用，样本身份按值保存；不拥有、关闭或取消 Session。
     */
    class RecognitionLatencyScope final
    {
    public:
        using Clock = std::chrono::steady_clock;

        /** @brief 开始计时；sink 为空时不读取时钟。 */
        RecognitionLatencyScope(
            std::shared_ptr<Preview::Foundation::RecognitionLatencySink> Sink,
            Preview::Foundation::RecognitionLatencySample Sample) noexcept
            : Sink_(std::move(Sink)), Sample_(Sample)
        {
            if (Sink_)
            {
                Started_ = Clock::now();
            }
        }

        RecognitionLatencyScope(const RecognitionLatencyScope &) = delete;
        auto operator=(const RecognitionLatencyScope &) -> RecognitionLatencyScope & = delete;

        /** @brief 所有返回与异常退栈路径都提交同一个数值样本。 */
        ~RecognitionLatencyScope() noexcept
        {
            if (!Sink_)
            {
                return;
            }
            const auto Elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - Started_).count();
            if (Elapsed > 0)
            {
                Sample_.DurationMicroseconds = static_cast<std::uint64_t>(Elapsed);
            }
            else
            {
                Sample_.DurationMicroseconds = 0U;
            }
            Sink_->ReportRecognitionLatency(Sample_);
        }

    private:
        std::shared_ptr<Preview::Foundation::RecognitionLatencySink> Sink_;
        Preview::Foundation::RecognitionLatencySample Sample_;
        Clock::time_point Started_{};
    };
}
