/**
 * @file OperationsEventProducer.hpp
 * @brief 管理命令接受与真实终态的事件环 producer
 * @details 仅应用命令 owner 在控制 executor 调用；事件记录是数值值快照，不保活操作资源。
 */
#pragma once

#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Statistics/EventRing.hpp>

#include <memory>

namespace Prism::Application::OperationsEventProducer
{
    /** @brief Accepted 与终态事件共享的不可变 operation 和 typed target 身份。 */
    struct Identity final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::Operations::OperationId Operation{};
        Prism::RequestId Correlation{};
        Prism::Operations::CommandTargetScope Target{};
    };

    /** @brief ProcessDrain 的预登记 operation、correlation 与完整 target。 */
    struct ProcessDrainIdentityInput final
    {
        Prism::Operations::OperationId Operation{};
        Prism::RequestId Correlation{};
        Prism::Operations::CommandTargetScope Target{};
    };

    /** @brief 向真实有界事件环追加事实；观察异常只增加观察失败数。 */
    auto Append(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        Prism::Statistics::DetailedEvent Event) noexcept -> void;

    /** @brief 构造已提交实际命令的 Accepted 非终态记录。 */
    [[nodiscard]] auto MakeAccepted(const Identity &Operation)
        -> Prism::Statistics::DetailedEvent;

    /** @brief 按真实终态构造 success 或 failure 记录。 */
    [[nodiscard]] auto MakeTerminal(const Identity &Operation, const bool Succeeded)
        -> Prism::Statistics::DetailedEvent;

    /** @brief 捕获 ProcessDrain 接受时稳定的 process、generation、operation 与 target 身份。 */
    [[nodiscard]] auto MakeProcessDrainIdentity(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        const ProcessDrainIdentityInput &Input) -> Identity;

    /** @brief 记录已开始运行的真实管理 operation。 */
    inline auto AppendAccepted(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        const Identity &Operation) noexcept -> void
    {
        Append(State, MakeAccepted(Operation));
    }

    /** @brief Router 确认终态后记录同一 operation 身份。 */
    inline auto AppendTerminal(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        const Identity &Operation,
        const bool Succeeded) noexcept -> void
    {
        Append(State, MakeTerminal(Operation, Succeeded));
    }

}
