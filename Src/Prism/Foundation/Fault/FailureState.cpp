/**
 * @file FailureState.cpp
 * @brief 首个失败值的原子发布实现。
 */
#include <Prism/Foundation/Fault/FailureState.hpp>

namespace Prism::Fault
{
    auto FailureState::TrySet(Failure Value) noexcept -> bool
    {
        if (Value.Succeeded()) return false;
        bool Empty = false;
        if (!Claimed_.compare_exchange_strong(Empty, true, std::memory_order_acq_rel)) return false;
        Value_ = Value;
        Ready_.store(true, std::memory_order_release);
        return true;
    }

    auto FailureState::Record(Failure Value) noexcept -> void
    {
        if (TrySet(Value)) return;
    }
}
