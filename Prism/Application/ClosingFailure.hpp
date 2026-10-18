/** @file ClosingFailure.hpp @brief 进程关闭失败观察者，weak 联系 RuntimeState 并沿控制 executor 停机。 */
#pragma once
#include <Prism/Application/Application.hpp>
#include <Prism/Application/Shutdown.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
namespace Prism::Application
{
    class ClosingFailure final : public Prism::Executor::ClosingFailureObserver
    {
    public:
        explicit ClosingFailure(const std::shared_ptr<Application::RuntimeState>& State)
            : State_(State), Reclaimer_(State->Io.get_executor()) {}
        /** @brief 任意线程通知，先禁止就绪，再投递正式 Shutdown；不强持进程 owner。 */
        auto OnDispatchUnavailable() noexcept -> void override
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
                { Shutdown::MarkShutdownFailed(State); State->StopRequested.store(true); Shutdown::ScheduleShutdown(State); }
            });
        }
    private:
        std::weak_ptr<Application::RuntimeState> State_;
        Prism::Executor::ExecutorReclaimer Reclaimer_;
    };
    /** @brief 在真实 RuntimeState 创建后登记唯一进程观察者；回滚/停机最后由原事务驱动。 */
    inline auto ObserveClosingFailures(const std::shared_ptr<Application::RuntimeState>& State) -> void
    {
        State->ClosingObserver = std::make_shared<ClosingFailure>(State);
        State->ClosingResources->Observe(State->ClosingObserver);
    }
}
