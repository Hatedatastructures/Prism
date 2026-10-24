/** @file ClosingFailure.cpp @brief 将关闭失败通知交给 Application 控制 executor。 */

#include <Prism/Application/ClosingFailure.hpp>
#include <Prism/Application/Shutdown.hpp>

#include <memory>

namespace Prism::Application
{

    ClosingFailure::ClosingFailure(
        const std::shared_ptr<Application::RuntimeState> &State)
        : State_(State), Reclaimer_(State->Io.get_executor())
    {
    }

    auto ClosingFailure::OnDispatchUnavailable() noexcept -> void
    {
        if (auto State = State_.lock())
        {
            State->ProtocolDrainFailed.store(true);
            State->Phase.store(RuntimePhase::Failed);
        }
        const auto Weak = State_;
        (void)Reclaimer_.Post([Weak]
        {
            if (auto State = Weak.lock())
            {
                Shutdown::MarkShutdownFailed(State);
                State->StopRequested.store(true);
                Shutdown::ScheduleShutdown(State);
            }
        });
    }

    auto ObserveClosingFailures(
        const std::shared_ptr<Application::RuntimeState> &State) -> void
    {
        State->ClosingObserver = std::make_shared<ClosingFailure>(State);
        State->ClosingResources->Observe(State->ClosingObserver);
    }

} // namespace Prism::Application
