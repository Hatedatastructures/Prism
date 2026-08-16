/**
 * @file cow_map.hpp
 * @brief 写时复制映射表（T5-3 O3，O6 复用）
 * @details 无锁读取 + CAS 写时复制：
 *          - snapshot：原子获取当前映射快照（shared_ptr<const>）
 *          - update：复制 → 修改 → CAS 替换（失败重试）
 *          - 读多写少场景（账户目录 / 会话注册表）
 * @note 模板化 Key/Value，不绑定账户类型；测试库自包含实现
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <utility>

namespace psmtest::account
{

    /**
     * @class cow_map
     * @brief 写时复制映射表
     * @tparam Key 键类型
     * @tparam Value 值类型
     * @tparam Compare 有序比较器
     */
    template <typename Key, typename Value, typename Compare = std::less<Key>>
    class cow_map
    {
    public:
        using map_t = std::map<Key, Value, Compare>; ///< 底层映射（有序，便于快照遍历）

        /**
         * @brief 构造
         */
        cow_map()
        {
            map_.store(std::make_shared<const map_t>());
        }

        /**
         * @brief 获取当前快照（无锁）
         * @return 映射快照（只读）
         */
        [[nodiscard]] auto snapshot() const noexcept -> std::shared_ptr<const map_t>
        {
            return map_.load(std::memory_order_acquire);
        }

        /**
         * @brief 查找键
         * @param key 键
         * @return 找到返回 true（值经 out 返回副本）
         */
        [[nodiscard]] auto find(const Key &key, Value &out) const -> bool
        {
            const auto snap = snapshot();
            const auto it = snap->find(key);
            if (it == snap->end())
            {
                return false;
            }
            out = it->second;
            return true;
        }

        /**
         * @brief 写入键值（写时复制）
         * @param key 键
         * @param value 值
         */
        void set(const Key &key, Value value)
        {
            update([&](map_t &m) { m[key] = std::move(value); });
        }

        /**
         * @brief 移除键（写时复制）
         * @param key 键
         * @return 存在并移除返回 true
         */
        auto remove(const Key &key) -> bool
        {
            bool removed = false;
            update([&](map_t &m) { removed = m.erase(key) > 0; });
            return removed;
        }

        /**
         * @brief 写时复制更新
         * @tparam UpdateFn 更新函数（接收可变 map_t&）
         * @param update_fn 更新操作
         * @details 复制当前快照 → 应用更新 → CAS 替换，失败重试
         */
        template <typename UpdateFn>
        void update(UpdateFn &&update_fn)
        {
            auto current = map_.load(std::memory_order_acquire);
            while (true)
            {
                auto next = std::make_shared<map_t>(*current);
                update_fn(*next);
                if (map_.compare_exchange_strong(current, next, std::memory_order_release,
                                                 std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        /**
         * @brief 元素数量
         */
        [[nodiscard]] auto size() const -> std::size_t
        {
            return snapshot()->size();
        }

        /**
         * @brief 清空
         */
        void clear()
        {
            map_.store(std::make_shared<const map_t>(), std::memory_order_release);
        }

    private:
        std::atomic<std::shared_ptr<const map_t>> map_; ///< 当前映射快照
    };

} // namespace psmtest::account
