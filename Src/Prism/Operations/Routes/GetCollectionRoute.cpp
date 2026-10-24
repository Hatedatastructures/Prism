/** @file GetCollectionRoute.cpp @brief Operations 顶层 GET 集合路由解析实现。 */
#include <Prism/Operations/Routes/GetCollectionRoute.hpp>
#include <Prism/Operations/Routes/RouteTarget.hpp>

#include <cstdint>
#include <expected>
#include <utility>

namespace Prism::Operations::RouteDispatch
{

    [[nodiscard]] auto MakeGetCollectionRoute(
        const TargetParts &Parts, const Prism::RequestId Correlation)
        -> std::expected<RouteValue, RouteFailure>
    {
        if (Parts.Segments[1] == "Metrics")
        {
            if (Parts.ParameterCount != 0U &&
                (Parts.ParameterCount != 1U || !FindParameter(Parts, "correlation")))
            {
                return std::unexpected(RouteFailure{400, "bad_query"});
            }
            return RouteValue{Query{MetricsQuery{Correlation}}};
        }
        if (Parts.Segments[1] == "Health")
        {
            if (Parts.ParameterCount != 0U &&
                (Parts.ParameterCount != 1U || !FindParameter(Parts, "correlation")))
            {
                return std::unexpected(RouteFailure{400, "bad_query"});
            }
            return RouteValue{Query{HealthQuery{Correlation}}};
        }
        if (Parts.Segments[1] == "Workers")
        {
            WorkerQuery Value;
            Value.Correlation = Correlation;
            std::uint64_t Id{};
            if (!MakePage(Parts, Value.Page))
            {
                return std::unexpected(RouteFailure{400, "bad_page"});
            }
            if (!TargetParameterReader(Parts).Unsigned("id", std::uint64_t{0}, Id))
            {
                return std::unexpected(RouteFailure{400, "bad_id"});
            }
            Value.Id = Prism::WorkerId{Id};
            return RouteValue{Query{std::move(Value)}};
        }
        if (Parts.Segments[1] == "Accounts")
        {
            AccountQuery Value;
            Value.Correlation = Correlation;
            std::uint64_t Id{};
            if (!MakePage(Parts, Value.Page))
            {
                return std::unexpected(RouteFailure{400, "bad_page"});
            }
            if (!TargetParameterReader(Parts).Unsigned("id", std::uint64_t{0}, Id))
            {
                return std::unexpected(RouteFailure{400, "bad_id"});
            }
            Value.Id = Prism::AccountId{Id};
            return RouteValue{Query{std::move(Value)}};
        }
        if (Parts.Segments[1] == "Sessions")
        {
            SessionQuery Value;
            Value.Correlation = Correlation;
            std::uint64_t Id{};
            if (!MakePage(Parts, Value.Page))
            {
                return std::unexpected(RouteFailure{400, "bad_page"});
            }
            if (!TargetParameterReader(Parts).Unsigned("id", std::uint64_t{0}, Id))
            {
                return std::unexpected(RouteFailure{400, "bad_id"});
            }
            Value.Id = Prism::SessionId{Id};
            return RouteValue{Query{std::move(Value)}};
        }
        if (Parts.Segments[1] == "Generations")
        {
            GenerationQuery Value;
            Value.Correlation = Correlation;
            std::uint64_t Id{};
            if (!TargetParameterReader(Parts).Unsigned("id", std::uint64_t{0}, Id))
            {
                return std::unexpected(RouteFailure{400, "bad_generation_id"});
            }
            Value.Id = Prism::GenerationId{Id};
            return RouteValue{Query{std::move(Value)}};
        }
        if (Parts.Segments[1] == "Configuration")
        {
            if (Parts.ParameterCount != 0U &&
                (Parts.ParameterCount != 1U || !FindParameter(Parts, "correlation")))
            {
                return std::unexpected(RouteFailure{400, "bad_query"});
            }
            return RouteValue{Query{ConfigurationQuery{Correlation}}};
        }
        if (Parts.Segments[1] == "Streams" || Parts.Segments[1] == "Tasks")
        {
            return std::unexpected(RouteFailure{400, "parent_identity_required"});
        }
        return std::unexpected(RouteFailure{404, "route_not_found"});
    }

} // namespace Prism::Operations::RouteDispatch
