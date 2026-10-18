/**
 * @file RouteDispatch.hpp
 * @brief Operations HTTP target registration、typed route construction 和异步 dispatch。
 * @details 该 header 只依赖值模型、Router 与 JSON owner；不拥有 listener、socket 或连接状态。
 */

#pragma once

#include <Prism/Operations/Routes/HttpJson.hpp>
#include <Prism/Operations/Routes/BootstrapJson.hpp>
#include <Prism/Operations/Routes/RequestParser.hpp>
#include <Prism/Operations/Web/Response.hpp>
#include <Prism/Operations/Routes/ReloadJson.hpp>
#include <Prism/Operations/Routes/RouteTarget.hpp>
#include <Prism/Operations/Routes/ScopedCollectionRoutes.hpp>
#include <Prism/Operations/Routes/QueryPageParser.hpp>
#include <Prism/Operations/Routes/GetCollectionRoute.hpp>
#include <Prism/Operations/Routes/ManagementRoutes.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace Prism::Operations::RouteDispatch
{

    [[nodiscard]] inline auto ReadRequiredUnsigned(
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

    [[nodiscard]] inline auto ReadCorrelation(const HttpRequest &Request,
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

    [[nodiscard]] inline auto MakeProcessGenerationRoute(
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

    [[nodiscard]] inline auto MakeStreamQueryRoute(
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

    [[nodiscard]] inline auto MakeStreamListQueryRoute(
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

    [[nodiscard]] inline auto MakeTaskQueryRoute(
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

    [[nodiscard]] inline auto MakeTaskListQueryRoute(
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

    [[nodiscard]] inline auto MakeOperationStatusRoute(
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

    [[nodiscard]] inline auto MakeGetRoute(const TargetParts &Parts,
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

    [[nodiscard]] inline auto MakeDrainRoute(
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

    [[nodiscard]] inline auto MakeReloadRoute(
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

    [[nodiscard]] inline auto MakeRevokeRoute(
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

    [[nodiscard]] inline auto MakeSessionCancelRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
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

    [[nodiscard]] inline auto MakeStreamResetRoute(
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

    [[nodiscard]] inline auto MakeTaskCancelRoute(
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

    [[nodiscard]] inline auto MakePostRoute(const TargetParts &Parts,
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

    [[nodiscard]] inline auto BuildRoute(const HttpRequest &Request,
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

    template <typename Value>
    [[nodiscard]] auto IncludesEventDetails(const Value &QueryValue) -> bool
    {
        if constexpr (std::is_same_v<std::remove_cvref_t<Value>, EventQuery>)
            return QueryValue.IncludeDetails;
        else
            return true;
    }

    template <typename StateValue>
    [[nodiscard]] inline auto Dispatch(const std::shared_ptr<StateValue> &State,
                                       const HttpRequest &Request,
                                       ResponseDeliveryReceipt Delivery)
        -> Net::awaitable<std::string>
    {
        if (!State->Bootstrap)
        {
            co_return HttpDetail::MakeErrorResponse(503, "bootstrap_unavailable");
        }
        if (!HttpDetail::RequestSecurity::IsAuthorized(
                Request, State->LocalEndpoint, *State->Bootstrap))
        {
            co_return HttpDetail::MakeErrorResponse(403, "forbidden");
        }
        if (Request.Method == "GET" && State->WebResources)
        {
            if (auto Resource = Web::MakeResourceResponse(*State->WebResources, Request.Target))
            {
                co_return std::move(*Resource);
            }
        }
        if (Request.Method == "GET" && Request.Target == "/Operations/Bootstrap")
        {
            const auto Body = HttpDetail::SerializeBootstrap(*State->Bootstrap);
            if (!Body)
            {
                co_return HttpDetail::MakeErrorResponse(500, "bootstrap_unavailable");
            }
            co_return HttpDetail::MakeNoStoreResponse(200, std::move(*Body));
        }
        const auto Route = BuildRoute(Request, State->NextCorrelation);
        if (!Route)
        {
            co_return HttpDetail::MakeErrorResponse(Route.error().Status, Route.error().Message);
        }
        if (const auto *QueryValue = std::get_if<Query>(&*Route))
        {
            const auto Result = co_await State->OperationsRouter.QueryAsync(*QueryValue);
            const auto IncludeDetails = std::visit(
                [](const auto &Value) { return IncludesEventDetails(Value); },
                QueryValue->Value);
            const auto Body = HttpDetail::SerializeQuery(Result, IncludeDetails);
            if (!Body)
            {
                co_return HttpDetail::MakeErrorResponse(500, "response_too_large", Result.Correlation);
            }
            co_return HttpDetail::MakeResponse(HttpDetail::StatusFor(Result.Status), std::move(*Body));
        }
        if (const auto *StatusValue = std::get_if<OperationStatusRoute>(&*Route))
        {
            const auto Result = co_await State->OperationsRouter.StatusAsync(
                StatusValue->Operation, StatusValue->Correlation);
            const auto Body = HttpDetail::SerializeCommand(Result);
            if (!Body)
            {
                co_return HttpDetail::MakeErrorResponse(500, "response_too_large", Result.Correlation);
            }
            co_return HttpDetail::MakeResponse(HttpDetail::StatusFor(Result.Status), std::move(*Body));
        }
        const auto Result = co_await State->OperationsRouter.ExecuteAsync(
            std::get<Command>(*Route), std::move(Delivery));
        const auto Body = HttpDetail::SerializeCommand(Result);
        if (!Body)
        {
            co_return HttpDetail::MakeErrorResponse(500, "response_too_large", Result.Correlation);
        }
        co_return HttpDetail::MakeResponse(HttpDetail::StatusFor(Result.Status), std::move(*Body));
    }

} // namespace Prism::Operations::RouteDispatch
