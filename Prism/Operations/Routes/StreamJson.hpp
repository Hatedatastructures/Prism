/** @file StreamJson.hpp @brief 管理响应中带完整父任务身份的 Mux stream JSON owner。 */
#pragma once

#include <Prism/Operations/Http/JsonWriter.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Routes/TrafficJson.hpp>

namespace Prism::Operations::HttpDetail
{
    template <typename Id>
    [[nodiscard]] inline auto AppendStreamId(JsonWriter &Writer, const Id Value) -> bool
    {
        return Writer.Decimal(Value.Value());
    }

    [[nodiscard]] inline auto AppendStream(JsonWriter &Writer, const StreamSnapshot &Value) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("id") || !AppendStreamId(Writer, Value.Id) ||
            !Writer.Append(",") || !Writer.Key("task") || !AppendStreamId(Writer, Value.Task) ||
            !Writer.Append(",") || !Writer.Key("parent_task") || !AppendStreamId(Writer, Value.ParentTask) ||
            !Writer.Append(",") || !Writer.Key("process") || !AppendStreamId(Writer, Value.Process) ||
            !Writer.Append(",") || !Writer.Key("session") || !AppendStreamId(Writer, Value.Session) ||
            !Writer.Append(",") || !Writer.Key("account") || !AppendStreamId(Writer, Value.Account) ||
            !Writer.Append(",") || !Writer.Key("worker") || !AppendStreamId(Writer, Value.Worker) ||
            !Writer.Append(",") || !Writer.Key("generation") || !AppendStreamId(Writer, Value.Generation) ||
            !Writer.Append(",") || !Writer.Key("traffic"))
        {
            return false;
        }
        if (Value.Traffic)
        {
            if (!AppendTraffic(Writer, *Value.Traffic)) return false;
        }
        else if (!Writer.Null())
        {
            return false;
        }
        if (!Writer.Append(",") || !Writer.Key("protocol") || !Writer.String(Value.Protocol) ||
            !Writer.Append(",") || !Writer.Key("state"))
        {
            return false;
        }
        if (Value.Active)
        {
            if (!Writer.String("active")) return false;
        }
        else if (!Writer.String("draining"))
        {
            return false;
        }
        return Writer.Append("}");
    }
}
