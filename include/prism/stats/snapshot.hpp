/**
 * @file snapshot.hpp
 * @brief 负载快照结构体
 * @details 记录工作线程的瞬时负载状态，用于负载均衡决策。
 */
#pragma once

#include <cstdint>

namespace psm::stats
{
    /**
     * @struct worker_load_snapshot
     * @brief 工作线程负载快照
     * @details 该结构体记录某一时刻工作线程的负载状态，用于负载均衡器
     * 计算评分。快照数据由工作线程定期上报，反映当前的会话负载、待处理
     * 任务队列深度以及事件循环的响应延迟。这三个指标共同决定工作线程的
     * 综合负载评分。
     */
    struct worker_load_snapshot
    {
        std::uint32_t active_sessions{0};   // 当前活跃的会话数量
        std::uint32_t pending_handoffs{0};  // 等待处理的移交任务数
        std::uint64_t event_loop_lag_us{0}; // 事件循环延迟，单位微秒
    };
} // namespace psm::stats
