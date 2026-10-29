/** @file ClosingFailure.hpp @brief 进程关闭失败观察者接口。 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>

#include <memory>

namespace Prism::Application
{

    class ClosingFailure final : public Prism::Executor::ClosingFailureObserver
    {
    public:
        explicit ClosingFailure(const std::shared_ptr<Application::RuntimeState> &State);
        auto OnDispatchUnavailable() noexcept -> void override;

    private:
        std::weak_ptr<Application::RuntimeState> State_;
        Prism::Executor::ExecutorReclaimer Reclaimer_;
    };

    /** @brief 登记唯一进程关闭失败观察者；最终停机由原事务驱动。 */
    auto ObserveClosingFailures(
        const std::shared_ptr<Application::RuntimeState> &State) -> void;

} // namespace Prism::Application
