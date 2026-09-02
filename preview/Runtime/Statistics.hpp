/**
 * @file Statistics.hpp
 * @brief 流量统计（T5-2 O2）
 * @details 协议/用户双维度流量聚合，三类计数器线程策略不同：
 *          - WorkerSlot：alignas(64) 原子槽（防伪共享）
 *          - PerWorkerTraffic：原子累加 + 聚合 POD
 *          - IdentityTraffic：按用户聚合（无锁 COW 快照，槽内原子累加）
 *          - TrafficCounter：无锁 COW 快照 + 条目内原子累加（协程零阻塞）
 * @note identity 首次出现时发布新快照，槽获取后累加原子化
 */

#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <preview/Foundation/Utility/TrafficSink.hpp>
#include <cstddef>
#include <cstdint>
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
        std::uint64_t Up{0};   ///< 上行字节
        std::uint64_t Down{0}; ///< 下行字节

        /**
         * @brief 合并
         */
        auto operator+=(const TrafficPod &other) -> TrafficPod &
        {
            Up += other.Up;
            Down += other.Down;
            return *this;
        }

        /**
         * @brief 相加
         */
        [[nodiscard]] auto operator+(const TrafficPod &other) const -> TrafficPod
        {
            auto R = *this;
            R += other;
            return R;
        }
    };

    /// 单 worker 流量槽（64 字节对齐，防伪共享）
    struct alignas(64) WorkerSlot
    {
        std::atomic<std::uint64_t> Up{0};   ///< 上行原子计数
        std::atomic<std::uint64_t> Down{0}; ///< 下行原子计数
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
        explicit PerWorkerTraffic(std::size_t workers) : Slots_(ClampWorkers(workers))
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
            if (worker >= Slots_.size())
            {
                return;
            }
            Slots_[worker].Up.fetch_add(up, std::memory_order_relaxed);
            Slots_[worker].Down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 读取单槽
         * @param worker worker 索引
         * @return 该 worker 累计（越界返回 0）
         */
        [[nodiscard]] auto Slot(std::size_t worker) const -> TrafficPod
        {
            if (worker >= Slots_.size())
            {
                return {};
            }
            return {Slots_[worker].Up.load(std::memory_order_relaxed),
                    Slots_[worker].Down.load(std::memory_order_relaxed)};
        }

        /**
         * @brief 聚合全部 worker
         */
        [[nodiscard]] auto Total() const -> TrafficPod
        {
            TrafficPod g;
            for (const auto &s : Slots_)
            {
                g.Up += s.Up.load(std::memory_order_relaxed);
                g.Down += s.Down.load(std::memory_order_relaxed);
            }
            return g;
        }

        /**
         * @brief worker 数
         */
        [[nodiscard]] auto WorkerCount() const -> std::size_t
        {
            return Slots_.size();
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

        std::vector<WorkerSlot> Slots_; ///< 每 worker 槽
    };

    /**
     * @class IdentityTraffic
     * @brief 按用户聚合流量
     * @details 每 identity 独立原子槽；已存在 identity 只读取不可变快照，
     *          新 identity 通过 CAS 发布写时复制快照，槽内 fetch_add 原子累加。
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
            Slot->Up.fetch_add(up, std::memory_order_relaxed);
            Slot->Down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 查询单用户
         * @param identity 用户标识
         * @return 累计（未出现返回 0）
         */
        [[nodiscard]] auto PerIdentity(std::string_view identity) const -> TrafficPod
        {
            const auto Snapshot = Snapshot_.load(std::memory_order_acquire);
            const auto It = Snapshot->find(std::string(identity));
            if (It == Snapshot->end())
            {
                return {};
            }
            return {It->second->Up.load(std::memory_order_relaxed),
                    It->second->Down.load(std::memory_order_relaxed)};
        }

        /**
         * @brief 全量快照（安全遍历）
         * @return (identity, pod) 列表
         */
        [[nodiscard]] auto All() const -> std::vector<std::pair<std::string, TrafficPod>>
        {
            const auto Snapshot = Snapshot_.load(std::memory_order_acquire);
            std::vector<std::pair<std::string, TrafficPod>> out;
            out.reserve(Snapshot->size());
            for (const auto &[Id, s] : *Snapshot)
            {
                out.emplace_back(Id, TrafficPod{s->Up.load(std::memory_order_relaxed),
                                                 s->Down.load(std::memory_order_relaxed)});
            }
            return out;
        }

        /**
         * @brief 用户数
         */
        [[nodiscard]] auto IdentityCount() const -> std::size_t
        {
            return Snapshot_.load(std::memory_order_acquire)->size();
        }

    private:
        /**
         * @brief 获取 identity 槽（不存在则发布新快照）
         */
        auto GetSlot(std::string_view identity) -> std::shared_ptr<WorkerSlot>
        {
            const auto Key = std::string(identity);
            auto Snapshot = Snapshot_.load(std::memory_order_acquire);
            std::shared_ptr<WorkerSlot> NewSlot;
            while (true)
            {
                if (const auto It = Snapshot->find(Key); It != Snapshot->end())
                {
                    return It->second;
                }

                if (!NewSlot)
                {
                    NewSlot = std::make_shared<WorkerSlot>();
                }
                auto Next = std::make_shared<Table>(*Snapshot);
                Next->emplace(Key, NewSlot);
                const auto Published = std::shared_ptr<const Table>(std::move(Next));
                if (Snapshot_.compare_exchange_weak(Snapshot, Published,
                                                     std::memory_order_acq_rel,
                                                     std::memory_order_acquire))
                {
                    return NewSlot;
                }
            }
        }

        using Table = std::unordered_map<std::string, std::shared_ptr<WorkerSlot>>;
        std::atomic<std::shared_ptr<const Table>> Snapshot_{
            std::make_shared<const Table>()}; ///< identity → 原子流量槽快照
    };

    /**
     * @class TrafficCounter
     * @brief 按 identity 聚合的流量计数器
     * @details 会话结束时 relay 中间件调用 Report()，
     *          本聚合器按 identity 累计 up/down。
     * @note 协程纯度：无锁 COW 快照实现，Report 在协程内零阻塞
     *       （替代旧阻塞方案）。Report 热路径仅 fetch_add；
     *       identity 首次出现时发布含新条目的新快照（写时复制），
     *       读取侧 load 不可变快照后对原子条目求和，全程无锁。
     */
    class TrafficCounter final : public Preview::Foundation::TrafficSink
    {
    public:
        /**
         * @struct Entry
         * @brief 单 identity 的流量
         */
        struct Entry
        {
            std::size_t Up{0};   ///< 上行字节
            std::size_t Down{0}; ///< 下行字节
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
            Slot->Up.fetch_add(up, std::memory_order_relaxed);
            Slot->Down.fetch_add(down, std::memory_order_relaxed);
        }

        /**
         * @brief 查询 identity 累计流量
         * @param identity 用户标识
         * @return 累计（未知 identity 返回 0）
         */
        [[nodiscard]] auto Total(std::string_view identity) const -> Entry
        {
            const auto Snap = Snapshot_.load(std::memory_order_acquire);
            const auto It = Snap->find(std::string(identity));
            if (It == Snap->end())
            {
                return {};
            }
            return {It->second->Up.load(std::memory_order_relaxed),
                    It->second->Down.load(std::memory_order_relaxed)};
        }

        /**
         * @brief 有流量的 identity 数
         */
        [[nodiscard]] auto IdentityCount() const -> std::size_t
        {
            return Snapshot_.load(std::memory_order_acquire)->size();
        }

        /**
         * @brief 全部 identity 累计流量
         */
        [[nodiscard]] auto GrandTotal() const -> Entry
        {
            const auto Snap = Snapshot_.load(std::memory_order_acquire);
            Entry g;
            for (const auto &[Id, e] : *Snap)
            {
                (void)Id;
                g.Up += e->Up.load(std::memory_order_relaxed);
                g.Down += e->Down.load(std::memory_order_relaxed);
            }
            return g;
        }

    private:
        /// 原子流量条目（Report 热路径 fetch_add，无锁）
        struct AtomicEntry
        {
            std::atomic<std::uint64_t> Up{0};   ///< 上行字节
            std::atomic<std::uint64_t> Down{0}; ///< 下行字节
        };
        using Table = std::map<std::string, std::shared_ptr<AtomicEntry>>;

        /**
         * @brief 取指定 identity 的条目；不存在时发布含新条目的新快照（COW）
         * @param identity 流量身份
         * @return 条目指针（永不为空）
         */
        auto SlotFor(std::string_view identity) -> std::shared_ptr<AtomicEntry>
        {
            auto Snap = Snapshot_.load(std::memory_order_acquire);
            while (true)
            {
                if (const auto It = Snap->find(std::string(identity)); It != Snap->end())
                {
                    return It->second;
                }
                auto Next = std::make_shared<Table>(*Snap);
                auto Slot = std::make_shared<AtomicEntry>();
                const auto SlotPtr = Slot.get();
                Next->emplace(std::string(identity), std::move(Slot));
                const auto NextPtr = std::shared_ptr<const Table>(std::move(Next));
                if (Snapshot_.compare_exchange_weak(Snap, NextPtr, std::memory_order_acq_rel,
                                                    std::memory_order_acquire))
                {
                    return std::shared_ptr<AtomicEntry>(NextPtr, SlotPtr);
                }
                // 竞败：snap 已被 compare_exchange_weak 更新为最新快照，重试查找
            }
        }

        std::atomic<std::shared_ptr<const Table>> Snapshot_{
            std::make_shared<const Table>()}; ///< identity → 流量（COW 快照）
    };

} // namespace Preview::Runtime
