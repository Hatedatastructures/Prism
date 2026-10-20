/** @file Models.cpp @brief Operations 命令目标身份映射实现。 */
#include <Prism/Operations/Models.hpp>

#include <variant>

namespace Prism::Operations
{
    auto ApplyCommandTarget(CommandResult &Result, const ProcessTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
    }

    auto ApplyCommandTarget(CommandResult &Result, const WorkerTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
    }

    auto ApplyCommandTarget(CommandResult &Result, const AccountTargetScope &Target) noexcept -> void
    {
        Result.Generation = Target.Generation;
        Result.Account = Target.Account;
    }

    auto ApplyCommandTarget(CommandResult &Result, const SessionTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
        Result.Session = Target.Session;
    }

    auto ApplyCommandTarget(CommandResult &Result, const StreamTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
        Result.Session = Target.Session;
        Result.Stream = Target.Stream;
        Result.ParentTask = Target.ParentTask;
        Result.Task = Target.Task;
    }

    auto ApplyCommandTarget(CommandResult &Result, const TaskTargetScope &Target) noexcept -> void
    {
        Result.Process = Target.Process;
        Result.Generation = Target.Generation;
        Result.Worker = Target.Worker;
        Result.Session = Target.Session;
        Result.Stream = Target.Stream;
        Result.ParentTask = Target.ParentTask;
        Result.Task = Target.Task;
    }

    auto ApplyCommandTarget(CommandResult &Result, const CommandTargetScope &Scope) noexcept -> void
    {
        std::visit([&Result](const auto &Target) { ApplyCommandTarget(Result, Target); }, Scope);
    }
}
