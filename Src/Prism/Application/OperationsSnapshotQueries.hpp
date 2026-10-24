/**
 * @file OperationsSnapshotQueries.hpp
 * @brief Application 所有的 Operations 健康与资源快照查询。
 */

#pragma once

#include <Prism/Account/Account.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <Prism/Statistics/Statistics.hpp>

#include <memory>
#include <variant>

namespace Prism::Application::OperationsStartup
{
    [[nodiscard]] inline auto InvalidOperationsQuery(const Prism::RequestId Correlation)
        -> Prism::Operations::QueryResult
    {
        return Prism::Operations::QueryResult{Correlation, Prism::Operations::QueryStatus::Invalid,
            std::monostate{}, "query_invalid"};
    }
    [[nodiscard]] auto MakeOperationsHealth(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::HealthQuery& QueryValue) -> Prism::Operations::QueryResult;

    [[nodiscard]] auto MakeOperationsWorkers(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::WorkerQuery& QueryValue) -> Prism::Operations::QueryResult;

    /** @brief 一次账户查询固定运行状态、generation 与同一发布记录的 admission。 */
    struct OperationsAccountQuerySnapshot final
    {
        std::shared_ptr<Application::RuntimeState> State;
        std::shared_ptr<const RuntimeGenerationSnapshot> Generation;
        Prism::Contract::AccountAdmissionAuthority::SnapshotPin Admission;
    };

    /** @brief 从唯一Binding派生账户值，不按配置位置重新猜测AccountId。 */
    [[nodiscard]] auto MakeOperationsAccount(
        const OperationsAccountQuerySnapshot &Snapshot,
        const std::shared_ptr<const Prism::Account::AccountBinding> &Binding)
        -> Prism::Operations::AccountSnapshot;
    [[nodiscard]] auto MakeOperationsAccounts(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::AccountQuery& QueryValue) -> Prism::Operations::QueryResult;

    [[nodiscard]] auto MakeOperationsSessions(const std::shared_ptr<Application::RuntimeState>& State,
        const Prism::Operations::SessionQuery& QueryValue) -> Prism::Operations::QueryResult;

    /** @brief 返回当前进程唯一已装配 generation 的值快照。 */
    [[nodiscard]] auto MakeOperationsGeneration(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::GenerationQuery &QueryValue)
        -> Prism::Operations::QueryResult;

} // namespace Prism::Application::OperationsStartup
