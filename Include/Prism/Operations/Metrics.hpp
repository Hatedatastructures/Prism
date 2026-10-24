/** @file Metrics.hpp @brief 进程实际流量、观察队列与有界采样的管理值契约。 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Statistics/TrafficHistory.hpp>
#include <Prism/Statistics/Snapshots.hpp>

#include <cstdint>
#include <vector>

namespace Prism::Operations
{
    /** @brief 控制 executor 上一次查询的自有值；不保活业务 session、stream 或代次资源。 */
    struct MetricsSnapshot final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{}; ///< 查询时唯一发布代次；累计流量包括仍有预约的退休代次。
        std::uint64_t CheckedAt{0}; ///< 本次实际读取的 Unix 毫秒，不合成缺失历史。
        Prism::Statistics::TrafficValue Traffic{};
        std::uint64_t AcceptedObservations{0}; ///< 实际入数值队列的事件。
        std::uint64_t ConsumedObservations{0}; ///< 实际从队列取出的事件，包含另外呈现的聚合失败。
        std::uint64_t DroppedObservations{0}; ///< 入队拒绝，与聚合失败独立。
        std::uint64_t AggregationFailures{0}; ///< 出队后的预算或聚合失败。
        std::uint64_t RecognitionLatencyQueueDrops{0}; ///< 延迟样本入队拒绝，包含在 DroppedObservations。
        std::uint64_t RecognitionLatencyAggregationFailures{0}; ///< 延迟样本无法归属代次槽的次数。
        Prism::Statistics::RetirementFailureSnapshot RetirementFailures{};
        std::uint64_t SampleIntervalMilliseconds{0}; ///< process collector 当前 timer 的实际周期。
        std::vector<Prism::Statistics::TrafficSample> History{}; ///< 仅实际已写样本，至多 1024 项。
        Prism::Statistics::RecognitionLatencySnapshot RecognitionLatency{}; ///< 与 Generation 严格匹配的 admission 样本。
    };

    /** @brief 只读进程统计查询；Correlation 是响应关联值，无取消或关闭业务资源的能力。 */
    struct MetricsQuery final
    {
        Prism::RequestId Correlation{};
    };
}
