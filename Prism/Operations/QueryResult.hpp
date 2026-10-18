/**
 * @file QueryResult.hpp
 * @brief Operations 查询结果状态和值模型。
 */

#pragma once

#include <Prism/Statistics/Statistics.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Operations/QueryPage.hpp>
#include <Prism/Operations/ScopedCollectionModels.hpp>
#include <Prism/Operations/ConfigurationIssue.hpp>
#include <Prism/Operations/ManagementModels.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Operations
{
    /** @brief 管理查询唯一结果状态。 */
    enum class QueryStatus : std::uint8_t
    {
        Ok,
        Unavailable,
        NotFound,
        Failed,
        Invalid,
    };

    using QueryPayload = std::variant<std::monostate,
                                      Prism::Statistics::HealthSnapshot,
                                      MetricsSnapshot,
                                      Prism::Statistics::GenerationSnapshot,
                                      ConfigurationSnapshot,
                                      Page<Prism::Statistics::WorkerSnapshot>,
                                      Page<Prism::Statistics::AccountSnapshot>,
                                      Page<Prism::Statistics::SessionSnapshot>,
                                      Page<Prism::Statistics::StreamSnapshot>,
                                      Page<Prism::Statistics::TaskSnapshot>,
                                      Prism::Statistics::EventPage,
                                      ManagementPayload>;

    /** @brief owning 查询结果、公开消息与固定 fault 值。 */
    struct QueryResult final
    {
        Prism::RequestId Correlation{};
        QueryStatus Status{QueryStatus::Unavailable};
        QueryPayload Value{};
        std::string Message{};
        Prism::Fault::Failure Failure{};

        [[nodiscard]] static auto Unavailable(const Prism::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Unavailable, std::monostate{},
                               "handler_unavailable"};
        }

        [[nodiscard]] static auto NotFound(const Prism::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::NotFound, std::monostate{},
                "stream_not_found"};
        }

        [[nodiscard]] static auto Invalid(const Prism::RequestId Correlation) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Invalid, std::monostate{},
                "invalid_query"};
        }

        [[nodiscard]] static auto Failed(
            const Prism::RequestId Correlation,
            Prism::Fault::Failure Failure) -> QueryResult
        {
            return QueryResult{
                Correlation, QueryStatus::Failed, std::monostate{}, "handler_failed", Failure};
        }

        [[nodiscard]] static auto Sessions(
            const Prism::RequestId Correlation,
            Page<Prism::Statistics::SessionSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Health(
            const Prism::RequestId Correlation,
            Prism::Statistics::HealthSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Metrics(const Prism::RequestId Correlation,
                                          MetricsSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Generation(
            const Prism::RequestId Correlation,
            Prism::Statistics::GenerationSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Configuration(
            const Prism::RequestId Correlation,
            ConfigurationSnapshot Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Workers(
            const Prism::RequestId Correlation,
            Page<Prism::Statistics::WorkerSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Accounts(
            const Prism::RequestId Correlation,
            Page<Prism::Statistics::AccountSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Streams(
            const Prism::RequestId Correlation,
            Page<Prism::Statistics::StreamSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Tasks(
            const Prism::RequestId Correlation,
            Page<Prism::Statistics::TaskSnapshot> Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }

        [[nodiscard]] static auto Events(
            const Prism::RequestId Correlation,
            Prism::Statistics::EventPage Value) -> QueryResult
        {
            return QueryResult{Correlation, QueryStatus::Ok, std::move(Value), {}};
        }
    };
} // namespace Prism::Operations
