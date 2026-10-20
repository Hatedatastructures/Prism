/** @file SessionRegistryMetadata.cpp @brief 查询真实会话 TaskRegistry 活动量。 */
#include <Prism/Runtime/SessionRegistry.hpp>

#include <cstdint>
#include <optional>

namespace Prism::Runtime
{
    auto SessionRegistry::ActiveTasks(const Prism::SessionId Id) const noexcept
        -> std::optional<std::uint64_t>
    {
        if (!State_ || !Id)
        {
            return std::nullopt;
        }
        const auto Current = State_->Records.load(std::memory_order_acquire);
        const auto It = Current->find(Id.Value());
        if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return std::nullopt;
        }
        const auto Control = Storage::GetActiveControl(It->second.Entry);
        if (!Control)
        {
            return std::nullopt;
        }
        const auto Active = Control->Metrics().Active;
        if (It->second.Entry->Removed.load(std::memory_order_seq_cst))
        {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(Active);
    }
}
