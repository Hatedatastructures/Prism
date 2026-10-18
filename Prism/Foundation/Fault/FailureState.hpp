/** @file FailureState.hpp @brief 一次发布、跨 executor 读取的唯一失败事实。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <atomic>
namespace Prism::Fault
{
    /** @brief owner 保活期间保存首个真实失败；发布后不可修改，不保存动态错误文本。 */
    class FailureState final
    {
    public:
        /** @brief 只允许一个失败发布者；成功值不占状态，不分配、不抛。 */
        [[nodiscard]] auto TrySet(Failure Value) noexcept -> bool
        {
            if (Value.Succeeded()) return false;
            bool Empty = false;
            if (!Claimed_.compare_exchange_strong(Empty, true, std::memory_order_acq_rel)) return false;
            Value_ = Value;
            Ready_.store(true, std::memory_order_release);
            return true;
        }
        /** @brief 获取完整不可变失败快照；尚未发布时为 Success，不代表资源已经退休。 */
        [[nodiscard]] auto Load() const noexcept -> Failure
        { if (!Ready_.load(std::memory_order_acquire)) return {}; return Value_; }
    private:
        std::atomic<bool> Claimed_{false}, Ready_{false};
        Failure Value_{};
    };
}
