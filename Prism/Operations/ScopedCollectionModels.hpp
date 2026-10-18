/**
 * @file ScopedCollectionModels.hpp
 * @brief 配置快照与完整父身份 collection 查询值。
 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Operations/QueryPage.hpp>

#include <string>

namespace Prism::Operations
{

    struct ConfigurationQuery final
    {
        Prism::RequestId Correlation{};
    };

    /** @brief 脱敏配置视图；Json 只含公共配置和 SecretRef，不含 secret 值或占位符。 */
    struct ConfigurationSnapshot final
    {
        Prism::GenerationId Generation{};
        bool Reloadable{false};
        std::string Json;
    };

    /** @brief 按完整 process/generation/worker/session 父身份分页列出真实 live streams。 */
    struct StreamListQuery final
    {
        Prism::RequestId Correlation{};
        PageRequest Page{};
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

    /** @brief 按完整 process/generation/worker/session 父身份分页列出该 session 的任务。 */
    struct TaskListQuery final
    {
        Prism::RequestId Correlation{};
        PageRequest Page{};
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

} // namespace Prism::Operations
