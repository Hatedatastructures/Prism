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
     * @struct worker_snapshot
     * @brief 单个 worker 的负载快照
     * @details 松散一致，适用于监控面板和日志输出
     */
    struct worker_snapshot
    {
        std::uint32_t active_sessions{0};       ///< 当前活跃会话数
        std::uint32_t pending_handoffs{0};      ///< 等待分发的连接数
        std::uint64_t loop_lag_us{0};     ///< 事件循环延迟（微秒，EMA 平滑后）
    };

    /**
     * @struct runtime_snapshot
     * @brief 全局运行状态快照
     * @details 由 system_state 单例产生，包含进程运行时间和 worker 数量
     */
    struct runtime_snapshot
    {
        std::uint64_t uptime_seconds{0};        ///< 进程运行时间（秒）
        std::uint32_t worker_count{0};           ///< 工作线程数量
    };

    // --- Traffic 快照 ---

    /**
     * @brief 协议槽位数组大小
     * @details 预留扩展空间，当前 protocol_type 枚举使用 0-6，
     * 未来可扩展 WebSocket、gRPC 等新协议而无需改内存布局。
     */
    static constexpr std::size_t proto_slot_count = 16;

    /**
     * @struct protocol_snapshot
     * @brief 单个协议维度的流量快照
     * @details 包含连接数、活跃连接数、上下行字节数四个指标
     */
    struct protocol_snapshot
    {
        std::uint64_t connections{0};            ///< 历史总连接数（仅增不减）
        std::uint64_t active{0};                 ///< 当前活跃连接数
        std::uint64_t uplink_bytes{0};           ///< 上行总字节数（含协议开销）
        std::uint64_t downlink_bytes{0};         ///< 下行总字节数（含协议开销）
    };

    /**
     * @struct traffic_snapshot
     * @brief 全局流量统计快照（含协议维度明细）
     * @details 由 traffic_state::aggregate() 聚合所有 worker 的计数器产生。
     * 数值为松散一致，不保证跨字段的原子性。
     */
    struct traffic_snapshot
    {
        std::uint64_t total_connections{0};      ///< 全局总连接数
        std::uint64_t total_active{0};           ///< 全局当前活跃连接数
        std::uint64_t total_uplink{0};           ///< 全局上行总字节
        std::uint64_t total_downlink{0};         ///< 全局下行总字节
        protocol_snapshot protocols[proto_slot_count]{};  ///< 按协议维度的流量明细
        std::uint64_t auth_success{0};           ///< 认证成功次数
        std::uint64_t auth_failure{0};           ///< 认证失败次数
    };
    // --- Memory 快照 ---

    /**
     * @struct memory_snapshot
     * @brief 内存分配统计快照
     * @details 由 memory_tracker 产生，包含全局 PMR 池的分配统计。
     * 数值为松散一致，不保证跨字段的原子性。
     */
    struct memory_snapshot
    {
        std::uint64_t total_allocated{0};    ///< 累计分配字节
        std::uint64_t total_deallocated{0};  ///< 累计释放字节
        std::uint64_t current_usage{0};      ///< 当前活跃字节
        std::uint64_t allocation_count{0};   ///< 分配次数
    };
} // namespace psm::stats
