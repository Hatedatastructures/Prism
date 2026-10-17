/** @file ManagementRoutes.hpp @brief 新增管理查询的 typed HTTP target 解析。 */
#pragma once

#include <Preview/Operations/Routes/QueryPageParser.hpp>

#include <expected>
#include <algorithm>
#include <limits>
#include <optional>
#include <string_view>

namespace Preview::Operations::RouteDispatch
{
    [[nodiscard]] inline auto IsAllowedManagementParameter(
        const TargetParts &Parts, const std::string_view Name) -> bool
    {
        for (std::size_t Index = 0; Index < Parts.ParameterCount; ++Index)
        {
            const auto Key = Parts.Parameters[Index].Name;
            if (Key == "correlation" || Key == "cursor" || Key == "limit" || Key == Name)
                continue;
            if (Name == "event_filters" && (Key == "include_details" || Key == "session_id" ||
                Key == "process_id" || Key == "worker_id" || Key == "account_id" || Key == "severity")) continue;
            return false;
        }
        return true;
    }

    [[nodiscard]] inline auto MakeManagementLimit(const TargetParts &Parts, PageRequest &Page) -> bool
    {
        std::uint64_t Limit{};
        if (!TargetParameterReader(Parts).Unsigned("limit", std::uint64_t{50}, Limit) ||
            Limit > std::numeric_limits<std::size_t>::max()) return false;
        Page.Limit = static_cast<std::size_t>(Limit);
        return true;
    }

    /** @brief 普通集合消费位置游标；Trace 的多 worker 游标由专属解析器消费。 */
    [[nodiscard]] inline auto MakeManagementPage(const TargetParts &Parts, PageRequest &Page) -> bool
    {
        return MakeManagementLimit(Parts, Page) &&
               TargetParameterReader(Parts).Unsigned("cursor", std::uint64_t{0}, Page.Cursor);
    }

    [[nodiscard]] inline auto ReadTraceCursors(
        const TargetParts &Parts, std::vector<TraceCursorSnapshot> &Cursors) -> bool
    {
        const auto Text = FindParameter(Parts, "cursor");
        if (!Text || *Text == "0") return true;
        auto Start = std::size_t{0};
        while (Start < Text->size())
        {
            const auto End = Text->find(',', Start);
            const auto Token = Text->substr(Start, End == std::string_view::npos
                ? Text->size() - Start : End - Start);
            const auto Separator = Token.find(':');
            std::uint64_t Worker{};
            std::uint64_t Sequence{};
            if (Separator == std::string_view::npos ||
                !RequestParserDetail::ParseUnsigned(Token.substr(0, Separator), Worker) || Worker == 0U ||
                !RequestParserDetail::ParseUnsigned(Token.substr(Separator + 1U), Sequence) ||
                std::any_of(Cursors.begin(), Cursors.end(), [Worker](const auto &Value)
                    { return Value.Worker.Value() == Worker; })) return false;
            Cursors.push_back({Preview::WorkerId{Worker}, Sequence});
            if (End == std::string_view::npos) break;
            Start = End + 1U;
        }
        return !Cursors.empty();
    }

    [[nodiscard]] inline auto ParseEventSeverity(const std::string_view Text)
        -> std::optional<Preview::Statistics::EventSeverity>
    {
        using Severity = Preview::Statistics::EventSeverity;
        if (Text == "debug") return Severity::Debug;
        if (Text == "info") return Severity::Info;
        if (Text == "warning") return Severity::Warning;
        if (Text == "error") return Severity::Error;
        return std::nullopt;
    }

    [[nodiscard]] inline auto MakeEventsRead(
        const TargetParts &Parts, const Preview::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        EventsRead Read;
        if (!IsAllowedManagementParameter(Parts, "event_filters") ||
            !MakePage(Parts, Read.Page) ||
            !TargetParameterReader(Parts).Boolean("include_details", true, Read.IncludeDetails))
            return std::unexpected(RouteFailure{400, "bad_query"});
        std::uint64_t Id{};
        if (const auto Value = FindParameter(Parts, "process_id"))
        {
            if (!RequestParserDetail::ParseUnsigned(*Value, Id) || Id == 0U)
                return std::unexpected(RouteFailure{400, "bad_process_id"});
            Read.Process = Preview::ProcessId{Id};
        }
        if (const auto Value = FindParameter(Parts, "worker_id"))
        {
            if (!RequestParserDetail::ParseUnsigned(*Value, Id) || Id == 0U)
                return std::unexpected(RouteFailure{400, "bad_worker_id"});
            Read.Worker = Preview::WorkerId{Id};
        }
        if (const auto Value = FindParameter(Parts, "account_id"))
        {
            if (!RequestParserDetail::ParseUnsigned(*Value, Id) || Id == 0U)
                return std::unexpected(RouteFailure{400, "bad_account_id"});
            Read.Account = Preview::AccountId{Id};
        }
        if (const auto Value = FindParameter(Parts, "session_id"))
        {
            if (!RequestParserDetail::ParseUnsigned(*Value, Id) || Id == 0U)
                return std::unexpected(RouteFailure{400, "bad_session_id"});
            Read.Session = Preview::SessionId{Id};
        }
        if (const auto Value = FindParameter(Parts, "severity"))
        {
            Read.Severity = ParseEventSeverity(*Value);
            if (!Read.Severity) return std::unexpected(RouteFailure{400, "bad_severity"});
        }
        ManagementQuery QueryValue{Correlation, ManagementQueryValue{std::move(Read)}};
        return RouteValue{Query{std::move(QueryValue)}};
    }

    [[nodiscard]] inline auto MakeTraceRead(
        const TargetParts &Parts, const Preview::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        SessionTraceRead Read;
        std::uint64_t Process{};
        std::uint64_t Session{};
        if (!IsAllowedManagementParameter(Parts, "") ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[2], Process) || Process == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[4], Session) || Session == 0U ||
            !MakeManagementLimit(Parts, Read.Page) || !ReadTraceCursors(Parts, Read.Cursors))
            return std::unexpected(RouteFailure{400, "bad_trace_query"});
        Read.Process = Preview::ProcessId{Process};
        Read.Session = Preview::SessionId{Session};
        ManagementQuery QueryValue{Correlation, ManagementQueryValue{std::move(Read)}};
        return RouteValue{Query{std::move(QueryValue)}};
    }

    [[nodiscard]] inline auto MakeManagementCollectionRoute(
        const TargetParts &Parts, const Preview::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        PageRequest Page;
        if (!IsAllowedManagementParameter(Parts, "") || !MakeManagementPage(Parts, Page))
            return std::unexpected(RouteFailure{400, "bad_query"});
        ManagementQueryValue Value;
        if (Parts.Segments[1] == "Ingresses") Value = IngressesRead{Page};
        else if (Parts.Segments[1] == "Groups") Value = GroupsRead{Page};
        else if (Parts.Segments[1] == "Protocols") Value = ProtocolsRead{Page};
        else if (Parts.Segments[1] == "Operations") Value = OperationsRead{Page};
        else if (Parts.Segments[1] == "Overview")
        {
            if (Parts.ParameterCount != 0U &&
                (Parts.ParameterCount != 1U || !FindParameter(Parts, "correlation")))
                return std::unexpected(RouteFailure{400, "bad_query"});
            Value = OverviewRead{};
        }
        else return std::unexpected(RouteFailure{404, "route_not_found"});
        return RouteValue{Query{ManagementQuery{Correlation, std::move(Value)}}};
    }

    [[nodiscard]] inline auto MakeManagementGetRoute(
        const TargetParts &Parts, const Preview::RequestId Correlation)
        -> std::optional<std::expected<RouteValue, RouteFailure>>
    {
        if (Parts.SegmentCount == 2U && Parts.Segments[0] == "Operations")
        {
            if (Parts.Segments[1] == "Events") return MakeEventsRead(Parts, Correlation);
            if (Parts.Segments[1] == "Overview" || Parts.Segments[1] == "Ingresses" ||
                Parts.Segments[1] == "Groups" || Parts.Segments[1] == "Protocols" ||
                Parts.Segments[1] == "Operations")
                return MakeManagementCollectionRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 6U && Parts.Segments[0] == "Operations" &&
            Parts.Segments[1] == "Processes" && Parts.Segments[3] == "Sessions" &&
            Parts.Segments[5] == "Trace") return MakeTraceRead(Parts, Correlation);
        return std::nullopt;
    }
}
