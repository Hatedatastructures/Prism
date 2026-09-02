/**
 * @file SessionRegistry.hpp
 * @brief 会话注册表（T5-7 O6）
 * @details 会话 Id → 信息的写时复制注册表：
 *          - Put/Remove/Find/Snapshot（值拷贝快照）
 *          - 快照为独立值拷贝：严禁持有内部引用（L3 资源隔离）
 * @note 复用 Account::CowMap（T5-3 O3 下沉）
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <preview/Foundation/Memory/CowMap.hpp>

namespace Preview::Runtime
{

    /**
     * @struct SessionInfo
     * @brief 会话信息（值语义 POD，快照可整体拷贝）
     */
    struct SessionInfo
    {
        std::uint64_t Id{0};         ///< 会话 Id
        std::string identity{};      ///< 用户标识
        std::string peer{};          ///< 远端地址
        std::string Target{};        ///< 目标地址
        std::uint16_t Protocol{0};   ///< 检测协议
        std::uint64_t StartedAt{0}; ///< 启动时刻
    };

    /**
     * @class SessionRegistry
     * @brief 会话注册表
     * @details COW 值拷贝快照：读多写少场景（管理 API 轮询）。
     *          快照 shared_ptr<const map> 独立持有值，不暴露内部引用。
     */
    class SessionRegistry
    {
    public:
        using MapT = std::map<std::uint64_t, SessionInfo>; ///< 底层映射

        /**
         * @brief 注册会话
         * @param Info 会话信息（按 Id 键控）
         */
        void Put(SessionInfo Info)
        {
            Map_.Set(Info.Id, std::move(Info));
        }

        /**
         * @brief 移除会话
         * @param Id 会话 Id
         * @return 存在并移除返回 true
         */
        auto Remove(std::uint64_t Id) -> bool
        {
            return Map_.Remove(Id);
        }

        /**
         * @brief 查找会话
         * @param Id 会话 Id
         * @param out 输出信息
         * @return 找到返回 true
         */
        [[nodiscard]] auto Find(std::uint64_t Id, SessionInfo &out) const -> bool
        {
            return Map_.Find(Id, out);
        }

        /**
         * @brief 当前数量
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            return Map_.Size();
        }

        /**
         * @brief 值拷贝快照（严禁 L3 引用外泄）
         * @return 只读快照（与注册表后续修改隔离）
         */
        [[nodiscard]] auto Snapshot() const noexcept -> std::shared_ptr<const MapT>
        {
            return Map_.Snapshot();
        }

    private:
        Preview::Memory::CowMap<std::uint64_t, SessionInfo> Map_; ///< 会话表
    };

} // namespace Preview::Runtime
