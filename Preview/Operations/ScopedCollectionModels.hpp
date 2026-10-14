/**
 * @file ScopedCollectionModels.hpp
 * @brief 配置快照与完整父身份 collection 查询值。
 */
#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Operations/QueryPage.hpp>

#include <string>

namespace Preview::Operations
{

    struct ConfigurationQuery final
    {
        Preview::RequestId Correlation{};
    };

    /** @brief 脱敏配置视图；Json 只含公共配置和 SecretRef，不含 secret 值或占位符。 */
    struct ConfigurationSnapshot final
    {
        Preview::GenerationId Generation{};
        bool Reloadable{false};
        std::string Json;
    };

    /** @brief 按完整 process/generation/worker/session 父身份分页列出真实 live streams。 */
    struct StreamListQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::SessionId Session{};
    };

    /** @brief 按完整 process/generation/worker/session 父身份分页列出该 session 的任务。 */
    struct TaskListQuery final
    {
        Preview::RequestId Correlation{};
        PageRequest Page{};
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::SessionId Session{};
    };

} // namespace Preview::Operations
