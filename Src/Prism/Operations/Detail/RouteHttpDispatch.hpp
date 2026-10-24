/** @file RouteHttpDispatch.hpp @brief HTTP 连接 owner 使用的路由响应异步分派实现。 */
#pragma once

#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/HttpRequestSecurity.hpp>
#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/ResponseDeliveryReceipt.hpp>
#include <Prism/Operations/Routes/BootstrapJson.hpp>
#include <Prism/Operations/Routes/HttpJson.hpp>
#include <Prism/Operations/Routes/RouteDispatch.hpp>
#include <Prism/Operations/Web/Response.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace Prism::Operations::Detail::RouteHttpDispatch
{
    template <typename Value>
    [[nodiscard]] auto IncludesEventDetails(const Value &QueryValue) -> bool
    {
        if constexpr (std::is_same_v<std::remove_cvref_t<Value>, ManagementQuery>)
        {
            const auto *Events = std::get_if<EventsRead>(&QueryValue.Value);
            return Events == nullptr || Events->IncludeDetails;
        }
        else
        {
            return true;
        }
    }

    template <typename StateValue>
    [[nodiscard]] inline auto Dispatch(const std::shared_ptr<StateValue> &State,
                                       const HttpRequest &Request,
                                       ResponseDeliveryReceipt Delivery)
        -> boost::asio::awaitable<std::string>
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
        const auto Route = RouteDispatch::BuildRoute(Request, State->NextCorrelation);
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
        if (const auto *StatusValue = std::get_if<RouteDispatch::OperationStatusRoute>(&*Route))
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
}
