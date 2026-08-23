/**
 * @file statistics.hpp
 * @brief 流量统计（T5-2 O2）
 * @details 协议/用户双维度流量聚合，三类计数器线程策略不同：
 *          - worker_slot：alignas(64) 原子槽（防伪共享）
 *          - per_worker_traffic：原子累加 + 聚合 POD
 *          - identity_traffic：按用户聚合（每次 add 经 mutex 取槽，槽内原子累加）
 *          - traffic_counter：无锁 COW 快照 + 条目内原子累加（协程零阻塞）
 * @note identity 首次出现时插入（锁），槽获取后累加原子化
 */

#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <common/core/middleware/context.hpp>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace preview::runtime
{

    /**
     * @struct traffic_pod
     * @brief 流量聚合 POD（可整体拷贝/合并）
     */
    struct traffic_pod
    {
        std::uint64_t up{0};   ///< 上行字节
        std::uint64_t down{0}; ///< 下行字节

        /**
         * @brief 合并
         */
        auto operator+=(const traffic_pod &other) -> traffic_pod &
        {
            up += other.up;
            down += other.down;
            return *this;
        }

        /**
         * @brief 相加
         */
        [[nodiscard]] auto operator+(const traffic_pod &other) const -> traffic_pod
        {
            auto r = *this;
            r += other;
            return r;
        }
    };

    /// 单 worker 流量槽（64 字节对齐，防伪共享）
    struct alignas(64) worker_slot
    {
        std::atomic<std::uint64_t> up{0};   ///< 上行原子计数
        std::atomic<std::uint64_t> down{0}; ///< 下行原子计数
    };

    /**
     * @class per_worker_traffic
     * @brief 每 worker 流量统计
     * @details add() 原子累加到指定 worker 槽；total() 聚合全部。
     *          协议维度由调用方按 worker 编号区分。
     */
    class per_worker_traffic
    {
    public:
        /**
         * @brief 构造
         * @param workers worker 数（≥1）
         */
        explicit per_worker_traffic(std::size_t workers) : slots_(clamp_workers(workers))
        {
        }

        /**
         * @brief 累加流量
         * @param worker worker 索引
         * @param up 上行字节
         * @param down 下行字节
         */
        void add(std::size_t worker, std::uint64_t up, std::uint64_t down)
        {
            if (worker >= slots_.size())
            {
                return;
            }
            slots_[worker].up.fetch_add(up, std::memory_order_relaxed);
            slots_[worker].down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 读取单槽
         * @param worker worker 索引
         * @return 该 worker 累计（越界返回 0）
         */
        [[nodiscard]] auto slot(std::size_t worker) const -> traffic_pod
        {
            if (worker >= slots_.size())
            {
                return {};
            }
            return {slots_[worker].up.load(std::memory_order_relaxed),
                    slots_[worker].down.load(std::memory_order_relaxed)};
        }

        /**
         * @brief 聚合全部 worker
         */
        [[nodiscard]] auto total() const -> traffic_pod
        {
            traffic_pod g;
            for (const auto &s : slots_)
            {
                g.up += s.up.load(std::memory_order_relaxed);
                g.down += s.down.load(std::memory_order_relaxed);
            }
            return g;
        }

        /**
         * @brief worker 数
         */
        [[nodiscard]] auto worker_count() const -> std::size_t
        {
            return slots_.size();
        }

    private:
        /// worker 数钳制（≥1）
        [[nodiscard]] static auto clamp_workers(const std::size_t workers) -> std::size_t
        {
            if (workers < 1)
            {
                return 1;
            }
            return workers;
        }

        std::vector<worker_slot> slots_; ///< 每 worker 槽
    };

    /**
     * @class identity_traffic
     * @brief 按用户聚合流量
     * @details 每 identity 独立原子槽；每次 add 经 mutex 获取/创建槽（锁粒度小，
     *          仅 map 查找），槽内 fetch_add 原子累加。快照遍历经锁安全。
     */
    class identity_traffic
    {
    public:
        /**
         * @brief 累加流量
         * @param identity 用户标识
         * @param up 上行字节
         * @param down 下行字节
         */
        void add(std::string_view identity, std::uint64_t up, std::uint64_t down)
        {
            auto slot = get_slot(identity);
            slot->up.fetch_add(up, std::memory_order_relaxed);
            slot->down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 查询单用户
         * @param identity 用户标识
         * @return 累计（未出现返回 0）
         */
        [[nodiscard]] auto per_identity(std::string_view identity) const -> traffic_pod
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto it = slots_.find(std::string(identity));
            if (it == slots_.end())
            {
                return {};
            }
            return {it->second->up.load(std::memory_order_relaxed),
                    it->second->down.load(std::memory_order_relaxed)};
        }

        /**
         * @brief 全量快照（安全遍历）
         * @return (identity, pod) 列表
         */
        [[nodiscard]] auto all() const -> std::vector<std::pair<std::string, traffic_pod>>
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::pair<std::string, traffic_pod>> out;
            out.reserve(slots_.size());
            for (const auto &[id, s] : slots_)
            {
                out.emplace_back(id, traffic_pod{s->up.load(std::memory_order_relaxed),
                                                 s->down.load(std::memory_order_relaxed)});
            }
            return out;
        }

        /**
         * @brief 用户数
         */
        [[nodiscard]] auto identity_count() const -> std::size_t
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return slots_.size();
        }

    private:
        /**
         * @brief 获取 identity 槽（不存在则插入）
         */
        auto get_slot(std::string_view identity) -> std::shared_ptr<worker_slot>
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto &slot = slots_[std::string(identity)];
            if (!slot)
            {
                slot = std::make_shared<worker_slot>();
            }
            return slot;
        }

        mutable std::mutex mutex_; ///< 插入锁
        std::unordered_map<std::string, std::shared_ptr<worker_slot>> slots_; ///< identity → 槽
    };

    /**
     * @class traffic_counter
     * @brief 按 identity 聚合的流量计数器
     * @details 会话结束时 relay 中间件调用 report()，
     *          本聚合器按 identity 累计 up/down。
     * @note 协程纯度：无锁 COW 快照实现，report 在协程内零阻塞
     *       （替代旧 std::mutex 方案）。report 热路径仅 fetch_add；
     *       identity 首次出现时发布含新条目的新快照（写时复制），
     *       读取侧 load 不可变快照后对原子条目求和，全程无锁。
     */
    class traffic_counter final : public preview::middleware::context::traffic_sink
    {
    public:
        /**
         * @struct entry
         * @brief 单 identity 的流量
         */
        struct entry
        {
            std::size_t up{0};   ///< 上行字节
            std::size_t down{0}; ///< 下行字节
        };

        /**
         * @brief 上报流量（relay 结束点调用）
         * @param identity 用户标识
         * @param up 上行字节
         * @param down 下行字节
         */
        void report(std::string_view identity, std::size_t up, std::size_t down) override
        {
            const auto slot = slot_for(identity);
            slot->up.fetch_add(up, std::memory_order_relaxed);
            slot->down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 查询 identity 累计流量
         * @param identity 用户标识
         * @return 累计（未知 identity 返回 0）
         */
        [[nodiscard]] auto total(std::string_view identity) const -> entry
        {
            const auto snap = snapshot_.load(std::memory_order_acquire);
            const auto it = snap->find(std::string(identity));
            if (it == snap->end())
            {
                return {};
            }
            return {it->second->up.load(std::memory_order_relaxed),
                    it->second->down.load(std::memory_order_relaxed)};
        }

        /**
         * @brief 有流量的 identity 数
         */
        [[nodiscard]] auto identity_count() const -> std::size_t
        {
            return snapshot_.load(std::memory_order_acquire)->size();
        }

        /**
         * @brief 全部 identity 累计流量
         */
        [[nodiscard]] auto grand_total() const -> entry
        {
            const auto snap = snapshot_.load(std::memory_order_acquire);
            entry g;
            for (const auto &[id, e] : *snap)
            {
                (void)id;
                g.up += e->up.load(std::memory_order_relaxed);
                g.down += e->down.load(std::memory_order_relaxed);
            }
            return g;
        }

    private:
        /// 原子流量条目（report 热路径 fetch_add，无锁）
        struct atomic_entry
        {
            std::atomic<std::uint64_t> up{0};   ///< 上行字节
            std::atomic<std::uint64_t> down{0}; ///< 下行字节
        };
        using table = std::map<std::string, std::shared_ptr<atomic_entry>>;

        /**
         * @brief 取指定 identity 的条目；不存在时发布含新条目的新快照（COW）
         * @param identity 流量身份
         * @return 条目指针（永不为空）
         */
        auto slot_for(std::string_view identity) -> std::shared_ptr<atomic_entry>
        {
            auto snap = snapshot_.load(std::memory_order_acquire);
            while (true)
            {
                if (const auto it = snap->find(std::string(identity)); it != snap->end())
                {
                    return it->second;
                }
                auto next = std::make_shared<table>(*snap);
                auto slot = std::make_shared<atomic_entry>();
                const auto slot_ptr = slot.get();
                next->emplace(std::string(identity), std::move(slot));
                const auto next_ptr = std::shared_ptr<const table>(std::move(next));
                if (snapshot_.compare_exchange_weak(snap, next_ptr, std::memory_order_acq_rel,
                                                    std::memory_order_acquire))
                {
                    return std::shared_ptr<atomic_entry>(next_ptr, slot_ptr);
                }
                // 竞败：snap 已被 compare_exchange_weak 更新为最新快照，重试查找
            }
        }

        std::atomic<std::shared_ptr<const table>> snapshot_{
            std::make_shared<const table>()}; ///< identity → 流量（COW 快照）
    };

} // namespace preview::runtime
