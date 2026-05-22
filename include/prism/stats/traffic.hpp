/**
 * @file traffic.hpp
 * @brief per-worker 流量统计 + 全局聚合
 * @details traffic_state 是 per-worker 单写者的流量计数器集合。
 * 所有热路径流量在局部变量累积，会话/子流结束时通过
 * flush_traffic() 批量刷入（4 次 fetch_add/会话）。
 * 全局聚合使用 COW 注册表，按需遍历。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

#include <prism/stats/snapshot.hpp>
#include <prism/protocol/protocol_type.hpp>

namespace psm::stats::traffic
{
    /**
     * @struct alignas(64) protocol_slot
     * @brief 单个协议维度的原子计数器组
     * @details 32 字节，2 个 slot 占一条缓存行。
     * 单写者场景下无需逐字段 alignas(64)。
     */
    struct alignas(64) protocol_slot
    {
        std::atomic<std::uint64_t> connections{0};
        std::atomic<std::uint64_t> active{0};
        std::atomic<std::uint64_t> uplink_bytes{0};
        std::atomic<std::uint64_t> downlink_bytes{0};
    };

    /**
     * @class alignas(64) traffic_state
     * @brief per-worker 流量计数器
     * @details 整个类 alignas(64) 确保不与 worker 其他成员
     * 共享缓存行。内部紧凑排列，因为只有一个写者（本 worker 线程）。
     */
    class alignas(64) traffic_state
    {
    public:
        traffic_state() = default;

        // 连接生命周期
        void on_connect() noexcept;
        void on_protocol_detected(protocol::protocol_type type) noexcept;
        void on_disconnect(protocol::protocol_type type) noexcept;

        // 批量流量刷入
        void flush_traffic(protocol::protocol_type proto,
                           std::uint64_t up,
                           std::uint64_t down) noexcept;

        // 认证
        void on_auth_success() noexcept;
        void on_auth_failure() noexcept;

        // 快照 + 归零
        [[nodiscard]] auto snapshot() const noexcept -> traffic_snapshot;
        void reset() noexcept;

        // 全局注册（COW 无锁）
        static void register_instance(traffic_state *s) noexcept;
        static void unregister_instance(traffic_state *s) noexcept;
        [[nodiscard]] static auto aggregate() noexcept -> traffic_snapshot;

    private:
        // 全局汇总
        std::atomic<std::uint64_t> total_connections_{0};
        std::atomic<std::uint64_t> total_active_{0};
        std::atomic<std::uint64_t> total_uplink_{0};
        std::atomic<std::uint64_t> total_downlink_{0};

        // 协议维度明细
        protocol_slot protocols_[protocol_slot_count];

        // 认证
        std::atomic<std::uint64_t> auth_success_{0};
        std::atomic<std::uint64_t> auth_failure_{0};
    };
} // namespace psm::stats::traffic
