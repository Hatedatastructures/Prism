/**
 * @file ManagementJson.hpp
 * @brief 新增管理查询的有界 owning JSON 序列化接口。
 */
#pragma once

#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Operations/Http/JsonWriter.hpp>
#include <Prism/Statistics/Snapshots.hpp>
#include <Prism/Statistics/Types.hpp>

#include <cstdint>
#include <optional>
#include <string_view>

namespace Prism::Operations::HttpDetail
{
    [[nodiscard]] auto ManagementHealthName(
        const Prism::Statistics::HealthStatus Value) -> std::string_view;

    [[nodiscard]] auto AppendManagementHealth(
        JsonWriter &Writer,
        const Prism::Statistics::HealthSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendManagementTraffic(
        JsonWriter &Writer,
        const Prism::Statistics::TrafficValue &Value) -> bool;

    [[nodiscard]] auto AppendOverviewTraffic(
        JsonWriter &Writer,
        const Prism::Operations::OverviewSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendOptionalDecimal(
        JsonWriter &Writer,
        const std::optional<std::uint64_t> &Value) -> bool;

    [[nodiscard]] auto AppendLatencySummary(
        JsonWriter &Writer,
        const Prism::Operations::LatencySummary &Value) -> bool;

    [[nodiscard]] auto AppendMemoryPool(
        JsonWriter &Writer,
        const Prism::Operations::MemoryPoolSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendMemoryAllocation(
        JsonWriter &Writer,
        const Prism::Operations::MemoryAllocationSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendIngress(
        JsonWriter &Writer,
        const Prism::Operations::IngressSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendGroup(
        JsonWriter &Writer,
        const Prism::Operations::GroupSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendProtocol(
        JsonWriter &Writer,
        const Prism::Operations::ProtocolSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendOperation(
        JsonWriter &Writer,
        const Prism::Operations::OperationSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendTraceSpan(
        JsonWriter &Writer,
        const Prism::Operations::TraceSpanSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendOverview(
        JsonWriter &Writer,
        const Prism::Operations::OverviewSnapshot &Value) -> bool;

    [[nodiscard]] auto AppendTracePage(
        JsonWriter &Writer,
        const Prism::Operations::TracePageSnapshot &Page) -> bool;

    [[nodiscard]] auto AppendManagementPayload(
        JsonWriter &Writer,
        const Prism::Operations::ManagementPayload &Payload) -> bool;
} // namespace Prism::Operations::HttpDetail
