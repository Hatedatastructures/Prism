/**
 * @file SessionRegistryMetadata.hpp
 * @brief 从已注册会话 owner 读取真实统计 metadata。
 */
#pragma once


#include <Prism/Runtime/SessionRegistryStorage.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>

namespace Prism::Runtime::Detail
{

    class SessionRegistryMetadata final
    {
    public:
        /** @brief 返回真实 SessionControl TaskRegistry 活动量；owner 不可用时为空。 */
        [[nodiscard]] static auto ActiveTasks(
            const std::shared_ptr<SessionRegistryState> &State,
            const Prism::SessionId Id) noexcept -> std::optional<std::uint64_t>
        {
            if (!State || !Id)
            {
                return std::nullopt;
            }
            const auto Current = State->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Id.Value());
            if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
            {
                return std::nullopt;
            }
            const auto Control = SessionRegistryStorage::GetActiveControl(It->second.Entry);
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

    };

} // namespace Prism::Runtime::Detail
