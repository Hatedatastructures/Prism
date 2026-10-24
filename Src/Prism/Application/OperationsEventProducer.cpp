/** @file OperationsEventProducer.cpp @brief Operations 接受与终态事件构造实现。 */
#include <Prism/Application/OperationsEventProducer.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>
#include <variant>

namespace Prism::Application::OperationsEventProducer
{
    namespace
    {
    struct EventSpec final
    {
        Prism::Statistics::EventKind Kind;
        Prism::Statistics::EventSeverity Severity;
        bool Terminal;
    };

    auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::ProcessTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Process;
        Event.Process = Target.Process;
    }

    auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::WorkerTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Worker;
        Event.Process = Target.Process;
        Event.Generation = Target.Generation;
        Event.Worker = Target.Worker;
    }

    auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::AccountTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Account;
        Event.Generation = Target.Generation;
        Event.Account = Target.Account;
    }

    auto ApplyTarget(
        Prism::Statistics::DetailedEvent &Event,
        const Prism::Operations::SessionTargetScope &Target) noexcept -> void
    {
        Event.ScopeValue = Prism::Statistics::Scope::Session;
        Event.Process = Target.Process;
        Event.Generation = Target.Generation;
        Event.Worker = Target.Worker;
        Event.Session = Target.Session;
    }

    auto ApplyTarget(
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

    auto ApplyTarget(
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

    [[nodiscard]] auto MakeEvent(
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
    }

    [[nodiscard]] auto MakeAccepted(const Identity &Operation)
        -> Prism::Statistics::DetailedEvent
    {
        return MakeEvent(Operation, EventSpec{
            Prism::Statistics::EventKind::OperationAccepted,
            Prism::Statistics::EventSeverity::Info, false});
    }

    [[nodiscard]] auto MakeTerminal(const Identity &Operation, const bool Succeeded)
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

    [[nodiscard]] auto MakeProcessDrainIdentity(
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

    auto Append(
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
