/** @file ScopedCollectionRoutes.hpp @brief Streams/Tasks 完整父作用域 collection route。 */
#pragma once

#include <Prism/Operations/QueryPage.hpp>
#include <Prism/Operations/Routes/RequestParser.hpp>
#include <Prism/Operations/Routes/RouteTarget.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>
#include <utility>

namespace Prism::Operations::ScopedCollectionRoutes
{
    namespace Route = Prism::Operations::RouteDispatch;
    namespace Parser = Prism::Operations::RequestParserDetail;
    namespace Operations = Prism::Operations;

    struct ProcessSessionScope final
    {
        Prism::ProcessId Process{};
        Prism::SessionId Session{};
    };

    struct ProcessWorkerSessionScope final
    {
        Prism::ProcessId Process{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

    [[nodiscard]] inline auto ReadRequired(
        const Route::TargetParts &Parts,
        const std::string_view Name,
        std::uint64_t &Value) -> bool
    {
        const auto Parameter = Route::FindParameter(Parts, Name);
        return Parameter && Parser::ParseUnsigned(*Parameter, Value);
    }

    [[nodiscard]] inline auto ParseProcessSession(const Route::TargetParts &Parts)
        -> std::optional<ProcessSessionScope>
    {
        std::uint64_t ProcessValue{};
        std::uint64_t SessionValue{};
        if (!Parser::ParseUnsigned(Parts.Segments[2], ProcessValue) ||
            ProcessValue == 0U ||
            !Parser::ParseUnsigned(Parts.Segments[4], SessionValue) ||
            SessionValue == 0U)
        {
            return std::nullopt;
        }
        return ProcessSessionScope{
            Prism::ProcessId{ProcessValue}, Prism::SessionId{SessionValue}};
    }

    [[nodiscard]] inline auto ParseProcessWorkerSession(const Route::TargetParts &Parts)
        -> std::optional<ProcessWorkerSessionScope>
    {
        std::uint64_t ProcessValue{};
        std::uint64_t WorkerValue{};
        std::uint64_t SessionValue{};
        if (!Parser::ParseUnsigned(Parts.Segments[2], ProcessValue) ||
            ProcessValue == 0U ||
            !Parser::ParseUnsigned(Parts.Segments[4], WorkerValue) ||
            WorkerValue == 0U ||
            !Parser::ParseUnsigned(Parts.Segments[6], SessionValue) ||
            SessionValue == 0U)
        {
            return std::nullopt;
        }
        return ProcessWorkerSessionScope{
            Prism::ProcessId{ProcessValue}, Prism::WorkerId{WorkerValue},
            Prism::SessionId{SessionValue}};
    }

    [[nodiscard]] inline auto MakeStreamQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>
    {
        const auto Scope = ParseProcessSession(Parts);
        std::uint64_t Stream{};
        std::uint64_t Generation{};
        std::uint64_t Worker{};
        if (!Scope ||
            !Parser::ParseUnsigned(Parts.Segments[6], Stream) || Stream == 0U ||
            !ReadRequired(Parts, "generation", Generation) || Generation == 0U ||
            !ReadRequired(Parts, "worker", Worker) || Worker == 0U)
        {
            return std::unexpected(Route::RouteFailure{400, "bad_stream_scope"});
        }
        Prism::Operations::StreamQuery Value;
        Value.Correlation = Correlation;
        Value.Page = Page;
        Value.Process = Scope->Process;
        Value.Session = Scope->Session;
        Value.Id = Prism::StreamId{Stream};
        Value.Generation = Prism::GenerationId{Generation};
        Value.Worker = Prism::WorkerId{Worker};
        return Route::RouteValue{Operations::Query{std::move(Value)}};
    }

    [[nodiscard]] inline auto MakeStreamListQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>
    {
        const auto Scope = ParseProcessSession(Parts);
        std::uint64_t Generation{};
        std::uint64_t Worker{};
        if (!Scope ||
            !ReadRequired(Parts, "generation", Generation) || Generation == 0U ||
            !ReadRequired(Parts, "worker", Worker) || Worker == 0U)
        {
            return std::unexpected(Route::RouteFailure{400, "bad_stream_scope"});
        }
        Prism::Operations::StreamListQuery Value;
        Value.Correlation = Correlation;
        Value.Page = Page;
        Value.Process = Scope->Process;
        Value.Session = Scope->Session;
        Value.Generation = Prism::GenerationId{Generation};
        Value.Worker = Prism::WorkerId{Worker};
        return Route::RouteValue{Operations::Query{std::move(Value)}};
    }

    [[nodiscard]] inline auto MakeTaskQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>
    {
        const auto Scope = ParseProcessWorkerSession(Parts);
        std::uint64_t Task{};
        std::uint64_t Generation{};
        std::uint64_t Stream{};
        std::uint64_t ParentTask{};
        if (!Scope ||
            !Parser::ParseUnsigned(Parts.Segments[8], Task) || Task == 0U ||
            !ReadRequired(Parts, "generation", Generation) || Generation == 0U ||
            !ReadRequired(Parts, "stream", Stream) ||
            !ReadRequired(Parts, "parent_task", ParentTask))
        {
            return std::unexpected(Route::RouteFailure{400, "bad_task_scope"});
        }
        Prism::Operations::TaskQuery Value;
        Value.Correlation = Correlation;
        Value.Page = Page;
        Value.Process = Scope->Process;
        Value.Worker = Scope->Worker;
        Value.Session = Scope->Session;
        Value.Id = Prism::TaskId{Task};
        Value.Generation = Prism::GenerationId{Generation};
        Value.Stream = Prism::StreamId{Stream};
        Value.ParentTask = Prism::TaskId{ParentTask};
        return Route::RouteValue{Operations::Query{std::move(Value)}};
    }

    [[nodiscard]] inline auto MakeTaskListQueryRoute(
        const Route::TargetParts &Parts,
        const Prism::RequestId Correlation,
        const Operations::PageRequest Page) -> std::expected<Route::RouteValue, Route::RouteFailure>
    {
        const auto Scope = ParseProcessWorkerSession(Parts);
        std::uint64_t Generation{};
        if (!Scope ||
            !ReadRequired(Parts, "generation", Generation) || Generation == 0U)
        {
            return std::unexpected(Route::RouteFailure{400, "bad_task_scope"});
        }
        Prism::Operations::TaskListQuery Value;
        Value.Correlation = Correlation;
        Value.Page = Page;
        Value.Process = Scope->Process;
        Value.Worker = Scope->Worker;
        Value.Session = Scope->Session;
        Value.Generation = Prism::GenerationId{Generation};
        return Route::RouteValue{Operations::Query{std::move(Value)}};
    }
}
