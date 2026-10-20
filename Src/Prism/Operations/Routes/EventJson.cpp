/** @file EventJson.cpp @brief 事件 JSON 编码实现。 */
#include <Prism/Operations/Routes/EventJson.hpp>

#include <Prism/Operations/Routes/TrafficJson.hpp>
#include <Prism/Operations/Detail/TrafficJsonSupport.hpp>

#include <string_view>

namespace Prism::Operations::HttpDetail
{
    /** @brief 映射事件环记录的实际分类。 */
    [[nodiscard]] auto EventKindName(
        const Prism::Statistics::EventKind Value) -> std::string_view
    {
        switch (Value)
        {
        case Prism::Statistics::EventKind::Data: return "data";
        case Prism::Statistics::EventKind::Started: return "started";
        case Prism::Statistics::EventKind::Failed: return "failed";
        case Prism::Statistics::EventKind::SessionClosed: return "session_closed";
        case Prism::Statistics::EventKind::StreamClosed: return "stream_closed";
        case Prism::Statistics::EventKind::TaskCompleted: return "task_completed";
        case Prism::Statistics::EventKind::TaskCanceled: return "task_canceled";
        case Prism::Statistics::EventKind::WorkerDrained: return "worker_drained";
        case Prism::Statistics::EventKind::GenerationReloaded: return "generation_reloaded";
        case Prism::Statistics::EventKind::OperationAccepted: return "operation_accepted";
        case Prism::Statistics::EventKind::OperationCompleted: return "operation_completed";
        case Prism::Statistics::EventKind::OperationFailed: return "operation_failed";
        }
        return "unknown";
    }

    /** @brief 映射事件环记录的实际目标作用域。 */
    [[nodiscard]] auto EventScopeName(
        const Prism::Statistics::Scope Value) -> std::string_view
    {
        switch (Value)
        {
        case Prism::Statistics::Scope::Process: return "process";
        case Prism::Statistics::Scope::Worker: return "worker";
        case Prism::Statistics::Scope::Account: return "account";
        case Prism::Statistics::Scope::Session: return "session";
        case Prism::Statistics::Scope::Stream: return "stream";
        case Prism::Statistics::Scope::Task: return "task";
        }
        return "unknown";
    }

    /** @brief 映射 EventRing producer 显式写入的真实 severity 枚举。 */
    [[nodiscard]] auto EventSeverityName(
        const Prism::Statistics::EventSeverity Value) -> std::string_view
    {
        switch (Value)
        {
        case Prism::Statistics::EventSeverity::Debug:
            return "debug";
        case Prism::Statistics::EventSeverity::Info:
            return "info";
        case Prism::Statistics::EventSeverity::Warning:
            return "warning";
        case Prism::Statistics::EventSeverity::Error:
            return "error";
        }
        return "unknown";
    }

    /** @brief 同步编码事件值；输入只在本次写入期间借用，不持有事件或日志 owner。 */
    [[nodiscard]] auto AppendEvent(
        JsonWriter &Writer,
        const EventSnapshot &Value,
        const bool IncludeDetails) -> bool
    {
        if (!Writer.Append("{") || !Writer.Key("sequence") || !Writer.Decimal(Value.Sequence) ||
            !Writer.Append(",") || !Writer.Key("timestamp") || !AppendUtcTimestamp(Writer, Value.Timestamp) ||
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

    /** @brief 输出真实事件页和丢失区间，并标明服务端支持 severity 过滤。 */
    [[nodiscard]] auto AppendEventPage(
        JsonWriter &Writer,
        const Prism::Statistics::EventPage &Page,
        const bool IncludeDetails) -> bool
    {
        if (!Writer.Append("{\"severity_filter_supported\":true,\"dropped\":") ||
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
