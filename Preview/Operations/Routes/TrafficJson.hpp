/** @file TrafficJson.hpp @brief 管理响应中可复用的流量快照 JSON owner。 */
#pragma once

#include <Preview/Operations/Http/JsonWriter.hpp>
#include <Preview/Statistics/Snapshots.hpp>

namespace Preview::Operations::HttpDetail
{
    [[nodiscard]] inline auto AppendTraffic(
        JsonWriter &Writer,
        const Preview::Statistics::TrafficValue &Value) -> bool
    {
        return Writer.Append("{") && Writer.Key("up_bytes") && Writer.Decimal(Value.UpBytes) &&
               Writer.Append(",") && Writer.Key("down_bytes") && Writer.Decimal(Value.DownBytes) &&
               Writer.Append(",") && Writer.Key("events") && Writer.Decimal(Value.Events) &&
               Writer.Append(",") && Writer.Key("errors") && Writer.Decimal(Value.Errors) &&
               Writer.Append("}");
    }
}
