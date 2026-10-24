/**
 * @file Facade.cpp
 * @brief Diagnose facade 的非模板级别预检实现。
 */
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>

#include <atomic>

namespace Prism::Diagnose::Detail
{
    auto IsEnabled(const LogLevel Requested) noexcept -> bool
    {
        auto& Slot = GetSubmissionSlot();
        if ((Slot.Admission.load(std::memory_order_acquire) & SubmissionSlot::ClosedBit) != 0U)
        {
            return false;
        }
        if (Requested == LogLevel::Critical)
        {
            return true;
        }
        const auto Configured = static_cast<LogLevel>(Slot.Level.load(std::memory_order_acquire));
        return IsEnabled(Configured, Requested);
    }

    auto IsEnabled(const ContextState &Context, const LogLevel Requested) noexcept -> bool
    {
        if ((GetSubmissionSlot().Admission.load(std::memory_order_acquire) &
                SubmissionSlot::ClosedBit) != 0U)
        {
            return false;
        }
        const auto Epoch = Context.RenderEpoch();
        if (!Epoch)
        {
            return Prism::Diagnose::Detail::IsEnabled(Requested);
        }
        return IsEnabled(Epoch->Value().Settings.Logging.Level, Requested);
    }
}
