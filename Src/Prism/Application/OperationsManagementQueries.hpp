/** @file OperationsManagementQueries.hpp @brief Overview、入口、组、协议、Operation 与 Trace 查询。 */
#pragma once

#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Application/OperationsManagementQuerySupport.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Contract/Ingress/Protocol.hpp>
#include <Prism/Foundation/Memory/ProcessMemory.hpp>
#include <Prism/Runtime/Statistics.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
#include <variant>

namespace Prism::Application::OperationsManagementQueries
{
    using QueryResult = Prism::Operations::QueryResult;

    [[nodiscard]] auto MakeAccountValues(const std::shared_ptr<RuntimeState> &State)
        -> std::vector<Prism::Operations::AccountSnapshot>;

    [[nodiscard]] auto UnixMilliseconds() -> std::uint64_t;

    [[nodiscard]] inline auto EndpointText(const auto &Endpoint) -> std::string
    {
        auto Address = Endpoint.address().to_string();
        if (Address.find(':') != std::string::npos) Address = "[" + Address + "]";
        return Address + ":" + std::to_string(Endpoint.port());
    }

    template <typename Value>
    [[nodiscard]] inline auto PageByOffset(
        const std::vector<Value> &Values, const Prism::Operations::PageRequest &Request)
        -> Prism::Operations::Page<Value>
    {
        Prism::Operations::Page<Value> Result;
        const auto Start = Request.Cursor > Values.size() ? Values.size()
            : static_cast<std::size_t>(Request.Cursor);
        const auto Count = Request.BoundedLimit();
        const auto End = (std::min)(Values.size(), Start + (std::min)(Count, Values.size() - Start));
        Result.Items.insert(Result.Items.end(), Values.begin() + static_cast<std::ptrdiff_t>(Start),
            Values.begin() + static_cast<std::ptrdiff_t>(End));
        Result.NextCursor = static_cast<std::uint64_t>(End);
        Result.HasMore = End < Values.size();
        return Result;
    }
    [[nodiscard]] auto ProtocolTypeForName(const std::string_view Name)
        -> std::optional<std::uint64_t>;

    [[nodiscard]] auto MakeProtocolSnapshots(
        const RuntimeState &State, const Prism::Application::RuntimeGenerationSnapshot &Generation)
        -> std::vector<Prism::Operations::ProtocolSnapshot>;

    auto PopulateMemorySnapshot(
        const RuntimeState &State, Prism::Operations::MemorySnapshot &Result) -> void;

    [[nodiscard]] auto MakeOverview(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::RequestId Correlation,
        const Prism::Statistics::HealthSnapshot &Health) -> QueryResult;

    [[nodiscard]] auto MakeGroups(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::GroupsRead &QueryValue,
        const Prism::RequestId Correlation)
        -> QueryResult;

    [[nodiscard]] auto MakeIngresses(
        const std::shared_ptr<RuntimeState> &State,
        const IngressesQueryRequest &Request) -> QueryResult;

    [[nodiscard]] auto MakeOperations(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::OperationsRead &QueryValue,
        const Prism::RequestId Correlation)
        -> QueryResult;
    [[nodiscard]] auto StageName(const Prism::Runtime::SessionTraceStage Stage) -> std::string_view;

    [[nodiscard]] auto MakeTrace(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::SessionTraceRead &Read,
        const Prism::RequestId Correlation)
        -> QueryResult;

    [[nodiscard]] auto MakeEvents(
        const std::shared_ptr<RuntimeState> &State, const Prism::Operations::EventsRead &Read,
        const Prism::RequestId Correlation) -> QueryResult;

    struct ManagementQueryDispatcher final
    {
        const std::shared_ptr<RuntimeState> &State;
        const Prism::Operations::ManagementQuery &Query;
        const Prism::Statistics::HealthSnapshot &Health;

        template <typename ValueObject>
        [[nodiscard]] auto operator()(const ValueObject &Value) const -> QueryResult
        {
            using ValueType = std::remove_cvref_t<ValueObject>;
            if constexpr (std::is_same_v<ValueType, Prism::Operations::OverviewRead>)
                return MakeOverview(State, Query.Correlation, Health);
            else if constexpr (std::is_same_v<ValueType, Prism::Operations::IngressesRead>)
                return MakeIngresses(State, IngressesQueryRequest{Value, Health, Query.Correlation});
            else if constexpr (std::is_same_v<ValueType, Prism::Operations::GroupsRead>)
                return MakeGroups(State, Value, Query.Correlation);
            else if constexpr (std::is_same_v<ValueType, Prism::Operations::ProtocolsRead>)
            {
                const auto Generation = State ? State->ActiveGenerationSnapshot() : nullptr;
                if (!Generation) return QueryResult::Unavailable(Query.Correlation);
                auto Items = MakeProtocolSnapshots(*State, *Generation);
                return QueryResult{Query.Correlation, Prism::Operations::QueryStatus::Ok,
                    Prism::Operations::ManagementPayload{PageByOffset(Items, Value.Page)}, {}};
            }
            else if constexpr (std::is_same_v<ValueType, Prism::Operations::OperationsRead>)
                return MakeOperations(State, Value, Query.Correlation);
            else if constexpr (std::is_same_v<ValueType, Prism::Operations::SessionTraceRead>)
                return MakeTrace(State, Value, Query.Correlation);
            else
                return MakeEvents(State, Value, Query.Correlation);
        }
    };

    [[nodiscard]] inline auto Dispatch(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::Operations::ManagementQuery &QueryValue,
        const Prism::Statistics::HealthSnapshot &Health) -> QueryResult
    {
        return std::visit(ManagementQueryDispatcher{State, QueryValue, Health}, QueryValue.Value);
    }
}
