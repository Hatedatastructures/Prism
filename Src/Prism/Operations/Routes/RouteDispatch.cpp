/** @file RouteDispatch.cpp @brief Operations typed 路由分发与请求解析实现。 */
#include <Prism/Operations/Routes/RouteDispatch.hpp>
#include <Prism/Operations/Routes/GetCollectionRoute.hpp>
#include <Prism/Operations/Routes/ManagementRoutes.hpp>
#include <Prism/Operations/Routes/ReloadJson.hpp>
#include <Prism/Operations/Routes/RequestParser.hpp>
#include <Prism/Operations/Routes/RouteTarget.hpp>
#include <Prism/Operations/Routes/ScopedCollectionRoutes.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>
#include <utility>

namespace Prism::Operations::RouteDispatch
{

    [[nodiscard]] auto ReadRequiredUnsigned(
        const TargetParts &Parts,
        const std::string_view Name,
        std::uint64_t &Result) -> bool
    {
        const auto Value = FindParameter(Parts, Name);
        if (!Value)
        {
            return false;
        }
        return RequestParserDetail::ParseUnsigned(*Value, Result);
    }

    [[nodiscard]] auto ReadCorrelation(const HttpRequest &Request,
                                              const TargetParts &Parts,
                                              std::atomic<std::uint64_t> &NextCorrelation) -> std::optional<Prism::RequestId>
    {
        auto Correlation = Request.Correlation;
        if (Correlation.empty())
        {
            const auto QueryCorrelation = FindParameter(Parts, "correlation");
            if (QueryCorrelation)
            {
                Correlation = *QueryCorrelation;
            }
        }
        if (Correlation.empty())
        {
            auto Next = NextCorrelation.fetch_add(1U, std::memory_order_relaxed);
            if (Next == 0U)
            {
                Next = NextCorrelation.fetch_add(1U, std::memory_order_relaxed);
            }
            const Prism::RequestId Result{Next};
            if (Result)
            {
                return Result;
            }
            return std::nullopt;
        }
        std::uint64_t Value{};
        if (!RequestParserDetail::ParseUnsigned(Correlation, Value) || Value == 0U)
        {
            return std::nullopt;
        }
        return Prism::RequestId{Value};
    }

    [[nodiscard]] auto MakeProcessGenerationRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        std::uint64_t Process{};
        std::uint64_t Generation{};
        if (!RequestParserDetail::ParseUnsigned(Parts.Segments[2], Process) || Process == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[4], Generation) || Generation == 0U)
        {
            return std::unexpected(RouteFailure{400, "bad_generation_scope"});
        }
        return RouteValue{Query{GenerationQuery{Correlation,
            Prism::ProcessId{Process}, Prism::GenerationId{Generation}}}};
    }

    [[nodiscard]] auto MakeStreamQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        PageRequest Page;
        if (!MakePage(Parts, Page))
        {
            return std::unexpected(RouteFailure{400, "bad_page"});
        }
        return ScopedCollectionRoutes::MakeStreamQueryRoute(Parts, Correlation, Page);
    }

    [[nodiscard]] auto MakeStreamListQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        PageRequest Page;
        if (!MakePage(Parts, Page))
        {
            return std::unexpected(RouteFailure{400, "bad_page"});
        }
        return ScopedCollectionRoutes::MakeStreamListQueryRoute(Parts, Correlation, Page);
    }

    [[nodiscard]] auto MakeTaskQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        PageRequest Page;
        if (!MakePage(Parts, Page))
        {
            return std::unexpected(RouteFailure{400, "bad_page"});
        }
        return ScopedCollectionRoutes::MakeTaskQueryRoute(Parts, Correlation, Page);
    }

    [[nodiscard]] auto MakeTaskListQueryRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        PageRequest Page;
        if (!MakePage(Parts, Page))
        {
            return std::unexpected(RouteFailure{400, "bad_page"});
        }
        return ScopedCollectionRoutes::MakeTaskListQueryRoute(Parts, Correlation, Page);
    }

    [[nodiscard]] auto MakeOperationStatusRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        std::uint64_t Value{};
        if (!RequestParserDetail::ParseUnsigned(Parts.Segments[2], Value) || Value == 0U)
        {
            return std::unexpected(RouteFailure{400, "bad_operation_id"});
        }
        return RouteValue{OperationStatusRoute{OperationId{Value}, Correlation}};
    }

    [[nodiscard]] auto MakeGetRoute(const TargetParts &Parts,
                                           const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        if (auto Management = MakeManagementGetRoute(Parts, Correlation))
            return std::move(*Management);
        if (Parts.SegmentCount == 5U && Parts.Segments[0] == "Operations" &&
            Parts.Segments[1] == "Processes" && Parts.Segments[3] == "Generations")
        {
            return MakeProcessGenerationRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 7U && Parts.Segments[0] == "Operations" &&
            Parts.Segments[1] == "Processes" && Parts.Segments[3] == "Sessions" &&
            Parts.Segments[5] == "Streams")
        {
            return MakeStreamQueryRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 6U && Parts.Segments[0] == "Operations" &&
            Parts.Segments[1] == "Processes" && Parts.Segments[3] == "Sessions" &&
            Parts.Segments[5] == "Streams")
        {
            return MakeStreamListQueryRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 9U && Parts.Segments[0] == "Operations" &&
            Parts.Segments[1] == "Processes" && Parts.Segments[3] == "Workers" &&
            Parts.Segments[5] == "Sessions" && Parts.Segments[7] == "Tasks")
        {
            return MakeTaskQueryRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 8U && Parts.Segments[0] == "Operations" &&
            Parts.Segments[1] == "Processes" && Parts.Segments[3] == "Workers" &&
            Parts.Segments[5] == "Sessions" && Parts.Segments[7] == "Tasks")
        {
            return MakeTaskListQueryRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 3U && Parts.Segments[0] == "Operations" &&
            Parts.Segments[1] == "Operations")
        {
            return MakeOperationStatusRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 2U && Parts.Segments[0] == "Operations")
        {
            return MakeGetCollectionRoute(Parts, Correlation);
        }
        return std::unexpected(RouteFailure{404, "route_not_found"});
    }

    [[nodiscard]] auto MakeDrainRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        std::uint64_t Worker{};
        bool Force{};
        if (FindParameter(Parts, "stop_accepting") ||
            !TargetParameterReader(Parts).Unsigned("worker", std::uint64_t{0}, Worker) ||
            !TargetParameterReader(Parts).Boolean("force", false, Force))
        {
            return std::unexpected(RouteFailure{400, "bad_command"});
        }
        if (Worker == 0U)
        {
            return RouteValue{Command{ProcessDrainCommand{Correlation, Force}}};
        }
        return RouteValue{Command{WorkerDrainCommand{Correlation,
            Prism::WorkerId{Worker}, Force}}};
    }

    [[nodiscard]] auto MakeReloadRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation,
        const std::string_view Body)
        -> std::expected<RouteValue, RouteFailure>
    {
        if (Parts.ParameterCount != 0U)
        {
            return std::unexpected(RouteFailure{400, "bad_command"});
        }
        const auto Document = ParseReloadDocument(Body);
        if (!Document)
        {
            if (Document.error() == ReloadDocumentError::Oversized)
            {
                return std::unexpected(RouteFailure{413, "request_too_large"});
            }
            return std::unexpected(RouteFailure{400, "bad_command"});
        }
        ReloadCommand Value;
        Value.Correlation = Correlation;
        Value.BaseGeneration = Document->BaseGeneration;
        Value.Mode = Document->Mode;
        Value.ConfigurationJson = Document->ConfigurationJson;
        return RouteValue{Command{std::move(Value)}};
    }

    [[nodiscard]] auto MakeRevokeRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        RevokeCommand Value;
        Value.Correlation = Correlation;
        std::uint64_t Account{};
        if (!RequestParserDetail::ParseUnsigned(Parts.Segments[2], Account) || Account == 0U ||
            !TargetParameterReader(Parts).Boolean("close_sessions", true, Value.CloseSessions))
        {
            return std::unexpected(RouteFailure{400, "bad_account_id"});
        }
        Value.Account = Prism::AccountId{Account};
        return RouteValue{Command{std::move(Value)}};
    }

    [[nodiscard]] auto MakeSessionCancelRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        if (FindParameter(Parts, "generation") || FindParameter(Parts, "worker") ||
            FindParameter(Parts, "stream") || FindParameter(Parts, "parent_task") ||
            FindParameter(Parts, "task"))
        {
            return std::unexpected(RouteFailure{400, "target_unsupported"});
        }

        CancelCommand Value;
        Value.Correlation = Correlation;
        std::uint64_t Process{};
        std::uint64_t Session{};
        if (!RequestParserDetail::ParseUnsigned(Parts.Segments[2], Process) || Process == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[4], Session) || Session == 0U)
        {
            return std::unexpected(RouteFailure{400, "bad_session_scope"});
        }
        Value.Process = Prism::ProcessId{Process};
        Value.Session = Prism::SessionId{Session};
        return RouteValue{Command{std::move(Value)}};
    }

    [[nodiscard]] auto MakeStreamResetRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        StreamResetCommand Value;
        Value.Correlation = Correlation;
        std::uint64_t Process{};
        std::uint64_t Session{};
        std::uint64_t Stream{};
        std::uint64_t Generation{};
        std::uint64_t Worker{};
        std::uint64_t ParentTask{};
        std::uint64_t Task{};
        if (!RequestParserDetail::ParseUnsigned(Parts.Segments[2], Process) || Process == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[4], Session) || Session == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[6], Stream) || Stream == 0U ||
            !ReadRequiredUnsigned(Parts, "generation", Generation) || Generation == 0U ||
            !ReadRequiredUnsigned(Parts, "worker", Worker) || Worker == 0U ||
            !ReadRequiredUnsigned(Parts, "parent_task", ParentTask) || ParentTask == 0U ||
            !ReadRequiredUnsigned(Parts, "task", Task) || Task == 0U)
        {
            return std::unexpected(RouteFailure{400, "bad_stream_scope"});
        }
        Value.Process = Prism::ProcessId{Process};
        Value.Generation = Prism::GenerationId{Generation};
        Value.Worker = Prism::WorkerId{Worker};
        Value.Session = Prism::SessionId{Session};
        Value.Stream = Prism::StreamId{Stream};
        Value.ParentTask = Prism::TaskId{ParentTask};
        Value.Task = Prism::TaskId{Task};
        return RouteValue{Command{std::move(Value)}};
    }

    [[nodiscard]] auto MakeTaskCancelRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        CancelCommand Value;
        Value.Correlation = Correlation;
        std::uint64_t Process{};
        std::uint64_t Worker{};
        std::uint64_t Session{};
        std::uint64_t Task{};
        std::uint64_t Generation{};
        std::uint64_t Stream{};
        std::uint64_t ParentTask{};
        if (!RequestParserDetail::ParseUnsigned(Parts.Segments[2], Process) || Process == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[4], Worker) || Worker == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[6], Session) || Session == 0U ||
            !RequestParserDetail::ParseUnsigned(Parts.Segments[8], Task) || Task == 0U ||
            !ReadRequiredUnsigned(Parts, "generation", Generation) || Generation == 0U ||
            !ReadRequiredUnsigned(Parts, "stream", Stream) ||
            !ReadRequiredUnsigned(Parts, "parent_task", ParentTask))
        {
            return std::unexpected(RouteFailure{400, "bad_task_scope"});
        }
        Value.Process = Prism::ProcessId{Process};
        Value.Worker = Prism::WorkerId{Worker};
        Value.Session = Prism::SessionId{Session};
        Value.Task = Prism::TaskId{Task};
        Value.Generation = Prism::GenerationId{Generation};
        Value.Stream = Prism::StreamId{Stream};
        Value.ParentTask = Prism::TaskId{ParentTask};
        return RouteValue{Command{std::move(Value)}};
    }

    [[nodiscard]] auto MakePostRoute(const TargetParts &Parts,
                                            const Prism::RequestId Correlation,
                                            const std::string_view Body)
        -> std::expected<RouteValue, RouteFailure>
    {
        if (Parts.SegmentCount < 2U || Parts.Segments[0] != "Operations")
        {
            return std::unexpected(RouteFailure{404, "route_not_found"});
        }
        if (Parts.SegmentCount == 2U && Parts.Segments[1] == "Drain")
        {
            return MakeDrainRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 2U && Parts.Segments[1] == "Reload")
        {
            return MakeReloadRoute(Parts, Correlation, Body);
        }
        if (Parts.SegmentCount == 4U && Parts.Segments[1] == "Accounts" &&
            Parts.Segments[3] == "Revoke")
        {
            return MakeRevokeRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 6U && Parts.Segments[1] == "Processes" &&
            Parts.Segments[3] == "Sessions" && Parts.Segments[5] == "Cancel")
        {
            return MakeSessionCancelRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 8U && Parts.Segments[1] == "Processes" &&
            Parts.Segments[3] == "Sessions" && Parts.Segments[5] == "Streams" &&
            Parts.Segments[7] == "Reset")
        {
            return MakeStreamResetRoute(Parts, Correlation);
        }
        if (Parts.SegmentCount == 10U && Parts.Segments[1] == "Processes" &&
            Parts.Segments[3] == "Workers" && Parts.Segments[5] == "Sessions" &&
            Parts.Segments[7] == "Tasks" && Parts.Segments[9] == "Cancel")
        {
            return MakeTaskCancelRoute(Parts, Correlation);
        }
        return std::unexpected(RouteFailure{404, "route_not_found"});
    }

    [[nodiscard]] auto BuildRoute(const HttpRequest &Request,
                                         std::atomic<std::uint64_t> &NextCorrelation)
        -> std::expected<RouteValue, RouteFailure>
    {
        TargetParts Parts;
        if (!ParseTarget(Request.Target, Parts))
        {
            return std::unexpected(RouteFailure{400, "bad_target"});
        }
        const auto Correlation = ReadCorrelation(Request, Parts, NextCorrelation);
        if (!Correlation)
        {
            return std::unexpected(RouteFailure{400, "bad_correlation"});
        }
        if (Request.Method == "GET")
        {
            return MakeGetRoute(Parts, *Correlation);
        }
        if (Request.Method == "POST")
        {
            return MakePostRoute(Parts, *Correlation, Request.Body);
        }
        return std::unexpected(RouteFailure{405, "method_not_allowed"});
    }

} // namespace Prism::Operations::RouteDispatch
