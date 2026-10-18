/** @file CommandTargetScope.hpp @brief 异步管理命令的精确目标身份及结果投影。 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>

#include <variant>

namespace Prism::Operations
{
    /** @brief 每种异步操作只携带其真实目标所需身份。 */
    /** @brief 进程级关闭操作的唯一目标。 */
    struct ProcessTargetScope final
    {
        Prism::ProcessId Process{};
    };

    /** @brief 单一 worker drain 的进程、代次与 worker 身份。 */
    struct WorkerTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
    };

    /** @brief 单一代次内账户撤销的目标。 */
    struct AccountTargetScope final
    {
        Prism::GenerationId Generation{};
        Prism::AccountId Account{};
    };

    /** @brief 单一父 session cancel 的真实父身份。 */
    struct SessionTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

    /** @brief 单一 mux child reset 的父、stream 与任务身份。 */
    struct StreamTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId ParentTask{};
        Prism::TaskId Task{};
    };

    /** @brief worker task retirement 的实际生命周期身份。 */
    struct TaskTargetScope final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId ParentTask{};
        Prism::TaskId Task{};
    };

    using CommandTargetScope = std::variant<
        ProcessTargetScope, WorkerTargetScope, AccountTargetScope,
        SessionTargetScope, StreamTargetScope, TaskTargetScope>;
}
