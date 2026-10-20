/** @file OperationsStreamQuery.hpp @brief 管理面 Mux stream 快照的精确身份查询。 */
#pragma once

#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Operations/Models.hpp>

#include <memory>
#include <optional>
#include <utility>

namespace Prism::Application::OperationsStartup
{
    /** @brief 把真实 catalog 能力缺失映射到既有 Unavailable 结果和 HTTP 503。 */
    [[nodiscard]] auto MakeStreamCatalogUnavailable(
        const Prism::RequestId Correlation) -> Prism::Operations::QueryResult;

    [[nodiscard]] auto MakeStreamSnapshot(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Contract::Ingress::StreamDescriptor &Value)
        -> std::optional<Prism::Operations::StreamSnapshot>;

    /** @brief 按完整父身份查询真实 Mux stream catalog；退休流返回 NotFound。 */
    [[nodiscard]] auto MakeOperationsStreamQuery(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::StreamQuery &QueryValue)
        -> Prism::Operations::QueryResult;

    /** @brief 按完整 session 父身份返回有界真实 stream registry 快照。 */
    [[nodiscard]] auto MakeOperationsStreamListQuery(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::StreamListQuery &QueryValue)
        -> Prism::Operations::QueryResult;
}
