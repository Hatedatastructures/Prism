/**
 * @file per_worker_traffic.hpp
 * @brief 每 worker 流量统计（T5-2 O2）
 * @details 协议/用户双维度流量聚合：
 *          - per_worker_traffic：alignas(64) 原子槽（防伪共享）+ 聚合 POD
 *          - identity_traffic：按用户聚合（独立原子槽）
 *          - traffic_pod：聚合结果 POD（可整体快照）
 * @note 原子无锁累加；身份聚合插入时锁（读多写少），累加无锁
 */

#pragma once

#include <atomic>
#include <map>
#include <string>
#include <string_view>
#include <common/core/middleware/context.hpp>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
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
     * @details 每 identity 独立原子槽；首次出现时插入（锁），
     *          之后原子累加（无锁）。快照遍历安全。
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
            auto &e = by_identity_[std::string(identity)];
            e.up += up;
            e.down += down;
        }

        /**
         * @brief 查询 identity 累计流量
         * @param identity 用户标识
         * @return 累计（未知 identity 返回 0）
         */
        [[nodiscard]] auto total(std::string_view identity) const -> entry
        {
            const auto it = by_identity_.find(std::string(identity));
            if (it == by_identity_.end())
            {
                return {};
            }
            return it->second;
        }

        /**
         * @brief 有流量的 identity 数
         */
        [[nodiscard]] auto identity_count() const -> std::size_t
        {
            return by_identity_.size();
        }

        /**
         * @brief 全部 identity 累计流量
         */
        [[nodiscard]] auto grand_total() const -> entry
        {
            entry g;
            for (const auto &[id, e] : by_identity_)
            {
                (void)id;
                g.up += e.up;
                g.down += e.down;
            }
            return g;
        }

    private:
        std::map<std::string, entry> by_identity_; ///< identity → 流量
    };

} // namespace preview::runtime
