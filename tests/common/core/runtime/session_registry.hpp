/**
 * @file session_registry.hpp
 * @brief 会话注册表（T5-7 O6）
 * @details 会话 id → 信息的写时复制注册表：
 *          - put/remove/find/snapshot（值拷贝快照）
 *          - 快照为独立值拷贝：严禁持有内部引用（L3 资源隔离）
 * @note 复用 account::cow_map（T5-3 O3 下沉）
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <common/core/account/cow_map.hpp>

namespace psmtest::runtime
{

    /**
     * @struct session_info
     * @brief 会话信息（值语义 POD，快照可整体拷贝）
     */
    struct session_info
    {
        std::uint64_t id{0};         ///< 会话 id
        std::string identity{};      ///< 用户标识
        std::string peer{};          ///< 远端地址
        std::string target{};        ///< 目标地址
        std::uint16_t protocol{0};   ///< 检测协议
        std::uint64_t started_at{0}; ///< 启动时刻
    };

    /**
     * @class session_registry
     * @brief 会话注册表
     * @details COW 值拷贝快照：读多写少场景（管理 API 轮询）。
     *          快照 shared_ptr<const map> 独立持有值，不暴露内部引用。
     */
    class session_registry
    {
    public:
        using map_t = std::map<std::uint64_t, session_info>; ///< 底层映射

        /**
         * @brief 注册会话
         * @param info 会话信息（按 id 键控）
         */
        void put(session_info info)
        {
            map_.set(info.id, std::move(info));
        }

        /**
         * @brief 移除会话
         * @param id 会话 id
         * @return 存在并移除返回 true
         */
        auto remove(std::uint64_t id) -> bool
        {
            return map_.remove(id);
        }

        /**
         * @brief 查找会话
         * @param id 会话 id
         * @param out 输出信息
         * @return 找到返回 true
         */
        [[nodiscard]] auto find(std::uint64_t id, session_info &out) const -> bool
        {
            return map_.find(id, out);
        }

        /**
         * @brief 当前数量
         */
        [[nodiscard]] auto size() const -> std::size_t
        {
            return map_.size();
        }

        /**
         * @brief 值拷贝快照（严禁 L3 引用外泄）
         * @return 只读快照（与注册表后续修改隔离）
         */
        [[nodiscard]] auto snapshot() const noexcept -> std::shared_ptr<const map_t>
        {
            return map_.snapshot();
        }

    private:
        psmtest::account::cow_map<std::uint64_t, session_info> map_; ///< 会话表
    };

} // namespace psmtest::runtime
