/**
 * @file snapshot.hpp
 * @brief 统计快照结构体
 * @details 所有统计模块的只读快照类型定义。快照是瞬时值的
 * 松散一致拷贝，适用于监控面板和日志输出，不用于精确计算。
 */
#pragma once

#include <cstdint>

namespace psm::stats
{
    // --- Runtime 快照 ---

    /**
     * @struct worker_load_snapshot
     * @brief 单个 worker 的负载快照
     */
    struct worker_load_snapshot
    {
        std::uint32_t active_sessions{0};
        std::uint32_t pending_handoffs{0};
        std::uint64_t event_loop_lag_us{0};
    };

    /**
     * @struct runtime_snapshot
     * @brief 全局运行状态快照
     */
    struct runtime_snapshot
    {
        std::uint64_t uptime_seconds{0};
        std::uint32_t worker_count{0};
    };

    // --- Traffic 快照 ---

    /**
     * @brief 协议槽位数组大小
     * @details 预留扩展空间，当前 protocol_type 枚举使用 0-6，
     * 未来可扩展 WebSocket、gRPC 等新协议而无需改内存布局。
     */
    static constexpr std::size_t protocol_slot_count = 16;

    /**
     * @struct protocol_snapshot
     * @brief 单个协议维度的流量快照
     */
    struct protocol_snapshot
    {
        std::uint64_t connections{0};
        std::uint64_t active{0};
        std::uint64_t uplink_bytes{0};
        std::uint64_t downlink_bytes{0};
    };

    /**
     * @struct traffic_snapshot
     * @brief 全局流量统计快照（含协议维度明细）
     */
    struct traffic_snapshot
    {
        std::uint64_t total_connections{0};
        std::uint64_t total_active{0};
        std::uint64_t total_uplink{0};
        std::uint64_t total_downlink{0};
        protocol_snapshot protocols[protocol_slot_count]{};
        std::uint64_t auth_success{0};
        std::uint64_t auth_failure{0};
    };
} // namespace psm::stats
