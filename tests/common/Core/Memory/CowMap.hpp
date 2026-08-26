/**
 * @file CowMap.hpp
 * @brief 写时复制映射表（T5-3 O3，O6 复用）
 * @details 无锁读取 + CAS 写时复制：
 *          - Snapshot：原子获取当前映射快照（shared_ptr<const>）
 *          - Update：复制 → 修改 → CAS 替换（失败重试）
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

namespace Preview::Memory
{

    /**
     * @class CowMap
     * @brief 写时复制映射表
     * @tparam Key 键类型
     * @tparam Value 值类型
     * @tparam Compare 有序比较器
     */
    template <typename Key, typename Value, typename Compare = std::less<Key>>
    class CowMap
    {
    public:
        using MapT = std::map<Key, Value, Compare>; ///< 底层映射（有序，便于快照遍历）

        /**
         * @brief 构造
         */
        CowMap()
        {
            Map_.store(std::make_shared<const MapT>());
        }

        /**
         * @brief 获取当前快照（无锁）
         * @return 映射快照（只读）
         */
        [[nodiscard]] auto Snapshot() const noexcept -> std::shared_ptr<const MapT>
        {
            return Map_.load(std::memory_order_acquire);
        }

        /**
         * @brief 查找键
         * @param key 键
         * @return 找到返回 true（值经 out 返回副本）
         */
        [[nodiscard]] auto Find(const Key &key, Value &out) const -> bool
        {
            const auto Snap = Snapshot();
            const auto It = Snap->find(key);
            if (It == Snap->end())
            {
                return false;
            }
            out = It->second;
            return true;
        }

        /**
         * @brief 写入键值（写时复制）
         * @param key 键
         * @param value 值
         */
        void Set(const Key &key, Value value)
        {
            // CAS 失败重试会再次执行 UpdateFn，value 必须保持可拷贝语义
            Update([&](MapT &m) { m[key] = value; });
        }

        /**
         * @brief 移除键（写时复制）
         * @param key 键
         * @return 存在并移除返回 true
         */
        auto Remove(const Key &key) -> bool
        {
            bool Removed = false;
            Update([&](MapT &m) { Removed = m.erase(key) > 0; });
            return Removed;
        }

        /**
         * @brief 写时复制更新
         * @tparam UpdateFn 更新函数（接收可变 MapT&）
         * @param UpdateFn 更新操作
         * @details 复制当前快照 → 应用更新 → CAS 替换，失败重试
         */
        template <typename UpdateFn>
        void Update(UpdateFn &&Fn)
        {
            auto Current = Map_.load(std::memory_order_acquire);
            while (true)
            {
                auto Next = std::make_shared<MapT>(*Current);
                Fn(*Next);
                if (Map_.compare_exchange_strong(Current, Next, std::memory_order_release,
                                                 std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        /**
         * @brief 元素数量
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            return Snapshot()->size();
        }

        /**
         * @brief 清空
         */
        void Clear()
        {
            Map_.store(std::make_shared<const MapT>(), std::memory_order_release);
        }

    private:
        std::atomic<std::shared_ptr<const MapT>> Map_; ///< 当前映射快照
    };

} // namespace Preview::Memory
