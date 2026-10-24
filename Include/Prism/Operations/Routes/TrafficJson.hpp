/** @file TrafficJson.hpp @brief 管理响应中可复用的流量快照 JSON owner。 */
#pragma once

#include <Prism/Operations/Http/JsonWriter.hpp>
#include <Prism/Statistics/Snapshots.hpp>

#include <cstdint>
#include <optional>

namespace Prism::Operations::HttpDetail
{
    /** @brief 输出下一个数组项的分隔符；不持有 writer 之外的状态。 */
    [[nodiscard]] auto AppendComma(JsonWriter& Writer, bool& First) -> bool;

    /** @brief 以明确的 UTC 毫秒精度输出 ISO-8601 时间；非法范围输出 null。 */
    [[nodiscard]] auto AppendUtcTimestamp(JsonWriter& Writer,
        const std::uint64_t Milliseconds) -> bool;

    /** @brief 零值表示未记录时间，不伪造 epoch 时间。 */
    [[nodiscard]] auto AppendOptionalUtcTimestamp(JsonWriter& Writer,
        const std::uint64_t Milliseconds) -> bool;

    [[nodiscard]] auto AppendOptionalUtcTimestamp(JsonWriter& Writer,
        const std::optional<std::uint64_t> Milliseconds) -> bool;

    [[nodiscard]] auto AppendTraffic(
        JsonWriter &Writer,
        const Prism::Statistics::TrafficValue &Value) -> bool;
}
