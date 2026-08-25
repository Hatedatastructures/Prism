/**
 * @file statistics.hpp
 * @brief 流量统计（T5-2 O2）
 * @details 协议/用户双维度流量聚合，三类计数器线程策略不同：
 *          - worker_slot：alignas(64) 原子槽（防伪共享）
 *          - PerWorkerTraffic：原子累加 + 聚合 POD
 *          - IdentityTraffic：按用户聚合（每次 Add 经 mutex 取槽，槽内原子累加）
 *          - TrafficCounter：无锁 COW 快照 + 条目内原子累加（协程零阻塞）
 * @note identity 首次出现时插入（锁），槽获取后累加原子化
 */

#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <common/Core/Middleware/Context.hpp>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Runtime
{

    /**
     * @struct TrafficPod
     * @brief 流量聚合 POD（可整体拷贝/合并）
     */
    struct TrafficPod
    {
        std::uint64_t up{0};   ///< 上行字节
        std::uint64_t down{0}; ///< 下行字节

        /**
         * @brief 合并
         */
        auto operator+=(const TrafficPod &other) -> TrafficPod &
        {
            up += other.up;
            down += other.down;
            return *this;
        }

        /**
         * @brief 相加
         */
        [[nodiscard]] auto operator+(const TrafficPod &other) const -> TrafficPod
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
     * @class PerWorkerTraffic
     * @brief 每 worker 流量统计
     * @details Add() 原子累加到指定 worker 槽；Total() 聚合全部。
     *          协议维度由调用方按 worker 编号区分。
     */
    class PerWorkerTraffic
    {
    public:
        /**
         * @brief 构造
         * @param workers worker 数（≥1）
         */
        explicit PerWorkerTraffic(std::size_t workers) : slots_(ClampWorkers(workers))
        {
        }

        /**
         * @brief 累加流量
         * @param worker worker 索引
         * @param up 上行字节
         * @param down 下行字节
         */
        void Add(std::size_t worker, std::uint64_t up, std::uint64_t down)
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
        [[nodiscard]] auto Slot(std::size_t worker) const -> TrafficPod
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
        [[nodiscard]] auto Total() const -> TrafficPod
        {
            TrafficPod g;
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
        [[nodiscard]] auto WorkerCount() const -> std::size_t
        {
            return slots_.size();
        }

    private:
        /// worker 数钳制（≥1）
        [[nodiscard]] static auto ClampWorkers(const std::size_t workers) -> std::size_t
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
     * @class IdentityTraffic
     * @brief 按用户聚合流量
     * @details 每 identity 独立原子槽；每次 Add 经 mutex 获取/创建槽（锁粒度小，
     *          仅 map 查找），槽内 fetch_add 原子累加。快照遍历经锁安全。
     */
    class IdentityTraffic
    {
    public:
        /**
         * @brief 累加流量
         * @param identity 用户标识
         * @param up 上行字节
         * @param down 下行字节
         */
        void Add(std::string_view identity, std::uint64_t up, std::uint64_t down)
        {
            auto Slot = GetSlot(identity);
            Slot->up.fetch_add(up, std::memory_order_relaxed);
            Slot->down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 查询单用户
         * @param identity 用户标识
         * @return 累计（未出现返回 0）
         */
        [[nodiscard]] auto PerIdentity(std::string_view identity) const -> TrafficPod
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
        [[nodiscard]] auto All() const -> std::vector<std::pair<std::string, TrafficPod>>
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::pair<std::string, TrafficPod>> out;
            out.reserve(slots_.size());
            for (const auto &[Id, s] : slots_)
            {
                out.emplace_back(Id, TrafficPod{s->up.load(std::memory_order_relaxed),
                                                 s->down.load(std::memory_order_relaxed)});
            }
            return out;
        }

        /**
         * @brief 用户数
         */
        [[nodiscard]] auto IdentityCount() const -> std::size_t
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return slots_.size();
        }

    private:
        /**
         * @brief 获取 identity 槽（不存在则插入）
         */
        auto GetSlot(std::string_view identity) -> std::shared_ptr<worker_slot>
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto &Slot = slots_[std::string(identity)];
            if (!Slot)
            {
                Slot = std::make_shared<worker_slot>();
            }
            return Slot;
        }

        mutable std::mutex mutex_; ///< 插入锁
        std::unordered_map<std::string, std::shared_ptr<worker_slot>> slots_; ///< identity → 槽
    };

    /**
     * @class TrafficCounter
     * @brief 按 identity 聚合的流量计数器
     * @details 会话结束时 relay 中间件调用 Report()，
     *          本聚合器按 identity 累计 up/down。
     * @note 协程纯度：无锁 COW 快照实现，Report 在协程内零阻塞
     *       （替代旧 std::mutex 方案）。Report 热路径仅 fetch_add；
     *       identity 首次出现时发布含新条目的新快照（写时复制），
     *       读取侧 load 不可变快照后对原子条目求和，全程无锁。
     */
    class TrafficCounter final : public Preview::Middleware::Context::TrafficSink
    {
    public:
        /**
         * @struct Entry
         * @brief 单 identity 的流量
         */
        struct Entry
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
        void Report(std::string_view identity, std::size_t up, std::size_t down) override
        {
            const auto Slot = SlotFor(identity);
            Slot->up.fetch_add(up, std::memory_order_relaxed);
            Slot->down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 查询 identity 累计流量
         * @param identity 用户标识
         * @return 累计（未知 identity 返回 0）
         */
        [[nodiscard]] auto Total(std::string_view identity) const -> Entry
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
        [[nodiscard]] auto IdentityCount() const -> std::size_t
        {
            return snapshot_.load(std::memory_order_acquire)->size();
        }

        /**
         * @brief 全部 identity 累计流量
         */
        [[nodiscard]] auto GrandTotal() const -> Entry
        {
            const auto snap = snapshot_.load(std::memory_order_acquire);
            Entry g;
            for (const auto &[Id, e] : *snap)
            {
                (void)Id;
                g.up += e->up.load(std::memory_order_relaxed);
                g.down += e->down.load(std::memory_order_relaxed);
            }
            return g;
        }

    private:
        /// 原子流量条目（Report 热路径 fetch_add，无锁）
        struct AtomicEntry
        {
            std::atomic<std::uint64_t> up{0};   ///< 上行字节
            std::atomic<std::uint64_t> down{0}; ///< 下行字节
        };
        using Table = std::map<std::string, std::shared_ptr<AtomicEntry>>;

        /**
         * @brief 取指定 identity 的条目；不存在时发布含新条目的新快照（COW）
         * @param identity 流量身份
         * @return 条目指针（永不为空）
         */
        auto SlotFor(std::string_view identity) -> std::shared_ptr<AtomicEntry>
        {
            auto snap = snapshot_.load(std::memory_order_acquire);
            while (true)
            {
                if (const auto it = snap->find(std::string(identity)); it != snap->end())
                {
                    return it->second;
                }
                auto next = std::make_shared<Table>(*snap);
                auto Slot = std::make_shared<AtomicEntry>();
                const auto SlotPtr = Slot.get();
                next->emplace(std::string(identity), std::move(Slot));
                const auto NextPtr = std::shared_ptr<const Table>(std::move(next));
                if (snapshot_.compare_exchange_weak(snap, NextPtr, std::memory_order_acq_rel,
                                                    std::memory_order_acquire))
                {
                    return std::shared_ptr<AtomicEntry>(NextPtr, SlotPtr);
                }
                // 竞败：snap 已被 compare_exchange_weak 更新为最新快照，重试查找
            }
        }

        std::atomic<std::shared_ptr<const Table>> snapshot_{
            std::make_shared<const Table>()}; ///< identity → 流量（COW 快照）
    };

} // namespace Preview::Runtime
