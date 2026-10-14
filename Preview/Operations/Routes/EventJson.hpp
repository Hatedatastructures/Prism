/** @file EventJson.hpp @brief 管理事件 severity、详情与丢失区间的 JSON owner。 */
#pragma once

#include <Preview/Operations/Models.hpp>
#include <Preview/Operations/Http/JsonWriter.hpp>
#include <Preview/Operations/Routes/JsonPrimitives.hpp>

#include <string_view>

namespace Preview::Operations::HttpDetail
{
    /** @brief 映射事件环记录的实际分类。 */
    [[nodiscard]] inline auto EventKindName(
        const Preview::Statistics::EventKind Value) -> std::string_view
    {
        switch (Value)
        {
        case Preview::Statistics::EventKind::Data: return "data";
        case Preview::Statistics::EventKind::Started: return "started";
        case Preview::Statistics::EventKind::Failed: return "failed";
        case Preview::Statistics::EventKind::SessionClosed: return "session_closed";
        case Preview::Statistics::EventKind::StreamClosed: return "stream_closed";
        case Preview::Statistics::EventKind::TaskCompleted: return "task_completed";
        case Preview::Statistics::EventKind::TaskCanceled: return "task_canceled";
        case Preview::Statistics::EventKind::WorkerDrained: return "worker_drained";
        case Preview::Statistics::EventKind::GenerationReloaded: return "generation_reloaded";
        case Preview::Statistics::EventKind::OperationAccepted: return "operation_accepted";
        case Preview::Statistics::EventKind::OperationCompleted: return "operation_completed";
        case Preview::Statistics::EventKind::OperationFailed: return "operation_failed";
        }
        return "unknown";
    }

    /** @brief 映射事件环记录的实际目标作用域。 */
    [[nodiscard]] inline auto EventScopeName(
        const Preview::Statistics::Scope Value) -> std::string_view
    {
        switch (Value)
        {
        case Preview::Statistics::Scope::Process: return "process";
        case Preview::Statistics::Scope::Worker: return "worker";
        case Preview::Statistics::Scope::Account: return "account";
        case Preview::Statistics::Scope::Session: return "session";
        case Preview::Statistics::Scope::Stream: return "stream";
        case Preview::Statistics::Scope::Task: return "task";
        }
        return "unknown";
    }

    /** @brief 映射 EventRing producer 显式写入的真实 severity 枚举。 */
    [[nodiscard]] inline auto EventSeverityName(
        const Preview::Statistics::EventSeverity Value) -> std::string_view
    {
        switch (Value)
        {
        case Preview::Statistics::EventSeverity::Debug:
            return "debug";
        case Preview::Statistics::EventSeverity::Info:
            return "info";
        case Preview::Statistics::EventSeverity::Warning:
            return "warning";
        case Preview::Statistics::EventSeverity::Error:
            return "error";
        }
        return "unknown";
    }

    /** @brief 同步编码事件值；输入只在本次写入期间借用，不持有事件或日志 owner。 */
    [[nodiscard]] inline auto AppendEvent(
        JsonWriter &Writer,
        const EventSnapshot &Value,
        const bool IncludeDetails) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("sequence") || !Writer.Decimal(Value.Sequence) ||
            !Writer.Append(",") || !Writer.Key("timestamp") || !Writer.Decimal(Value.Timestamp) ||
            !Writer.Append(",") || !Writer.Key("kind") || !Writer.String(EventKindName(Value.Kind)) ||
            !Writer.Append(",") || !Writer.Key("operation") || !Writer.Decimal(Value.Operation) ||
            !Writer.Append(",") || !Writer.Key("scope") || !Writer.String(EventScopeName(Value.ScopeValue)) ||
            !Writer.Append(",") || !Writer.Key("correlation") || !AppendId(Writer, Value.Correlation) ||
            !Writer.Append(",") || !Writer.Key("generation") || !AppendId(Writer, Value.Generation) ||
            !Writer.Append(",") || !Writer.Key("process") || !AppendId(Writer, Value.Process) ||
            !Writer.Append(",") || !Writer.Key("worker") || !AppendId(Writer, Value.Worker) ||
            !Writer.Append(",") || !Writer.Key("account") || !AppendId(Writer, Value.Account) ||
            !Writer.Append(",") || !Writer.Key("session") || !AppendId(Writer, Value.Session) ||
            !Writer.Append(",") || !Writer.Key("stream") || !AppendId(Writer, Value.Stream) ||
            !Writer.Append(",") || !Writer.Key("parent_task") || !AppendId(Writer, Value.ParentTask) ||
            !Writer.Append(",") || !Writer.Key("task") || !AppendId(Writer, Value.Task) ||
            !Writer.Append(",") || !Writer.Key("severity") ||
            !Writer.String(EventSeverityName(Value.Severity)) ||
            !Writer.Append(",") || !Writer.Key("terminal") || !Writer.Boolean(Value.Terminal) ||
            !Writer.Append(",") || !Writer.Key("truncated") || !Writer.Boolean(Value.Truncated))
        {
            return false;
        }
        if (IncludeDetails &&
            (!Writer.Append(",") || !Writer.Key("detail") || !Writer.String(Value.Detail)))
        {
            return false;
        }
        return Writer.Append("}");
    }

    /** @brief 输出真实事件页和丢失区间，并明确服务端 severity 过滤不可用。 */
    [[nodiscard]] inline auto AppendEventPage(
        JsonWriter &Writer,
        const Preview::Statistics::EventPage &Page,
        const bool IncludeDetails) -> bool
    {
        if (!Writer.Append("{\"severity_filter_supported\":false,\"dropped\":") ||
            !Writer.Decimal(Page.Dropped) || !Writer.Append(",\"terminal_dropped\":") ||
            !Writer.Decimal(Page.TerminalDropped) || !Writer.Append(",\"overwritten\":") ||
            !Writer.Decimal(Page.Overwritten) || !Writer.Append(",\"items\":["))
        {
            return false;
        }
        bool First = true;
        for (const auto &Event : Page.Items)
        {
            if (!AppendComma(Writer, First) || !AppendEvent(Writer, Event, IncludeDetails))
            {
                return false;
            }
        }
        if (!Writer.Append("],\"next_cursor\":") || !Writer.Decimal(Page.NextCursor) ||
            !Writer.Append(",\"has_more\":") || !Writer.Boolean(Page.HasMore) ||
            !Writer.Append(",\"earliest_cursor\":") || !Writer.Decimal(Page.EarliestCursor) ||
            !Writer.Append(",\"lost\":") || !Writer.Boolean(Page.Lost) ||
            !Writer.Append(",\"lost_ranges\":["))
        {
            return false;
        }
        First = true;
        for (const auto &Range : Page.LostRanges)
        {
            if (!AppendComma(Writer, First) || !Writer.Append("{\"first\":") ||
                !Writer.Decimal(Range.First) || !Writer.Append(",\"last\":") ||
                !Writer.Decimal(Range.Last) || !Writer.Append("}"))
            {
                return false;
            }
        }
        return Writer.Append("]}");
    }
}
