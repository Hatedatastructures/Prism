/**
 * @file EwmaMeter.cpp
 * @brief 指数加权移动平均速率计实现。
 */
#include <Prism/Foundation/Utility/Diagnose/Observability.hpp>

#include <cmath>

namespace Prism::Diagnose
{
    EwmaMeter::EwmaMeter(const std::uint64_t WindowMs) : WindowMs_(1), LastRead_(Uninit)
    {
        if (WindowMs > 0)
        {
            WindowMs_ = WindowMs;
        }
    }

    auto EwmaMeter::Mark(const std::uint64_t N) -> void
    {
        Sum_.fetch_add(N, std::memory_order_relaxed);
    }

    auto EwmaMeter::RatePerSecond(const std::uint64_t Now) const -> double
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
}
