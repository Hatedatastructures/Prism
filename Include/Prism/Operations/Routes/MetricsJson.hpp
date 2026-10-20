/** @file MetricsJson.hpp @brief 真实采样与观察计数的有界 JSON 序列化接口。 */
#pragma once

#include <Prism/Operations/Http/JsonWriter.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Statistics/Snapshots.hpp>
#include <Prism/Statistics/TrafficHistory.hpp>

#include <cstdint>
#include <optional>
#include <vector>

namespace Prism::Operations::HttpDetail
{
    /** @brief 只序列化 owner 交付的实际历史；不会补零、插值或生成占位点。 */
    [[nodiscard]] auto AppendHistory(
        JsonWriter &Writer,
        const std::vector<Prism::Statistics::TrafficSample> &Samples) -> bool;

    /** @brief 分别呈现入队、聚合、丢弃与退休失败，不能把观察失败计入业务 Errors。 */
    [[nodiscard]] auto AppendObservations(
        JsonWriter &Writer,
        const MetricsSnapshot &Value) -> bool;

    /** @brief 无样本时明确输出 JSON null，不用零值冒充实际分位数。 */
    [[nodiscard]] auto AppendOptionalMicroseconds(
        JsonWriter &Writer,
        const std::optional<std::uint64_t> Value) -> bool;

    /** @brief 写入指定代次真实样本、近似分位数和已发布的近期值。 */
    [[nodiscard]] auto AppendRecognitionLatency(
        JsonWriter &Writer,
        const Prism::Statistics::RecognitionLatencySnapshot &Value) -> bool;

    /** @brief 拒绝跨代、虚构无样本分位数或超出真实样本边界的快照。 */
    [[nodiscard]] auto IsValidRecognitionLatency(
        const Prism::Statistics::RecognitionLatencySnapshot &Value,
        const Prism::GenerationId Generation) noexcept -> bool;

    /** @brief 值快照输出，不保存输入引用；空历史明确 history_ready=false。 */
    [[nodiscard]] auto AppendMetrics(
        JsonWriter &Writer,
        const MetricsSnapshot &Value) -> bool;
}
