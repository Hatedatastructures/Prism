/**
 * @file OperationsEventProducer.hpp
 * @brief 管理命令接受与真实终态的事件环 producer
 * @details 仅应用命令 owner 在控制 executor 调用；事件记录是数值值快照，不保活操作资源。
 */
#pragma once

#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Operations/CommandTargetScope.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Statistics/EventRing.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>
#include <variant>

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

    /** @brief 一条有界事件记录的分类、severity 和终态事实。 */
    struct EventSpec final
    {
        Prism::Statistics::EventKind Kind{Prism::Statistics::EventKind::OperationAccepted};
        Prism::Statistics::EventSeverity Severity{Prism::Statistics::EventSeverity::Info};
        bool Terminal{false};
    };

    inline auto Append(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        Prism::Statistics::DetailedEvent Event) noexcept -> void;

    /** @brief 将 typed command target 投影为唯一 Event scope 和身份字段。 */
    inline auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::ProcessTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Process;
        Event.Process = Target.Process;
    }

    inline auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::WorkerTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Worker;
        Event.Process = Target.Process;
        Event.Generation = Target.Generation;
        Event.Worker = Target.Worker;
    }

    inline auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::AccountTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Account;
        Event.Generation = Target.Generation;
        Event.Account = Target.Account;
    }

    inline auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::SessionTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Session;
        Event.Process = Target.Process;
        Event.Generation = Target.Generation;
        Event.Worker = Target.Worker;
        Event.Session = Target.Session;
    }

    inline auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::StreamTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Stream;
        Event.Process = Target.Process;
        Event.Generation = Target.Generation;
        Event.Worker = Target.Worker;
        Event.Session = Target.Session;
        Event.Stream = Target.Stream;
        Event.ParentTask = Target.ParentTask;
        Event.Task = Target.Task;
    }

    inline auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::TaskTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Task;
        Event.Process = Target.Process;
        Event.Generation = Target.Generation;
        Event.Worker = Target.Worker;
        Event.Session = Target.Session;
        Event.Stream = Target.Stream;
        Event.ParentTask = Target.ParentTask;
        Event.Task = Target.Task;
    }

    /** @brief 构造只含值和数值身份的事件；不保活业务 owner。 */
    [[nodiscard]] inline auto MakeEvent(
        const Identity &Operation,
        const EventSpec &Specification) -> Prism::Statistics::DetailedEvent
    {
        Prism::Statistics::DetailedEvent Event;
        Event.Timestamp = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        Event.Correlation = Operation.Correlation;
        Event.Generation = Operation.Generation;
        Event.Process = Operation.Process;
        Event.Operation = Operation.Operation.Value();
        Event.Kind = Specification.Kind;
        Event.Severity = Specification.Severity;
        Event.Terminal = Specification.Terminal;
        std::visit([&Event](const auto &Target) { ApplyTarget(Event, Target); }, Operation.Target);
        if (!Event.Generation)
        {
            Event.Generation = Operation.Generation;
        }
        return Event;
    }

    /** @brief 构造已提交实际命令的 Accepted 非终态记录。 */
    [[nodiscard]] inline auto MakeAccepted(const Identity &Operation)
        -> Prism::Statistics::DetailedEvent
    {
        return MakeEvent(Operation, EventSpec{
            Prism::Statistics::EventKind::OperationAccepted,
            Prism::Statistics::EventSeverity::Info, false});
    }

    /** @brief 按真实终态构造 success 或 failure 记录。 */
    [[nodiscard]] inline auto MakeTerminal(const Identity &Operation, const bool Succeeded)
        -> Prism::Statistics::DetailedEvent
    {
        if (Succeeded)
        {
            return MakeEvent(Operation, EventSpec{
                Prism::Statistics::EventKind::OperationCompleted,
                Prism::Statistics::EventSeverity::Info, true});
        }
        return MakeEvent(Operation, EventSpec{
            Prism::Statistics::EventKind::OperationFailed,
            Prism::Statistics::EventSeverity::Error, true});
    }

    /** @brief 捕获 ProcessDrain 接受时稳定的 process、generation、operation 与 target 身份。 */
    [[nodiscard]] inline auto MakeProcessDrainIdentity(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        const ProcessDrainIdentityInput &Input) -> Identity
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        if (State && State->Process)
        {
            Process = State->Process->Id();
            const auto Snapshot = State->ActiveGenerationSnapshot();
            if (Snapshot)
            {
                Generation = Snapshot->Id();
            }
        }
        return Identity{Process, Generation, Input.Operation, Input.Correlation, Input.Target};
    }

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

    /** @brief 向真实有界事件环追加事实；观察异常只增加观察失败数。 */
    inline auto Append(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        Prism::Statistics::DetailedEvent Event) noexcept -> void
    {
        if (!State || !State->Events)
        {
            if (State)
            {
                State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
            }
            return;
        }
        try
        {
            if (!State->Events->Append(std::move(Event)))
            {
                State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
            }
        }
        catch (...)
        {
            State->ObservationFailures.fetch_add(1U, std::memory_order_relaxed);
        }
    }
}
