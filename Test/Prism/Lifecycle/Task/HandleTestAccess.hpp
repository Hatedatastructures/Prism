/** @file HandleTestAccess.hpp @brief 生命周期用例对任务私有状态的精确观察入口。 */
#pragma once

#include <Prism/Lifecycle/Task/State.hpp>

namespace Prism::Lifecycle
{
    /** @brief 仅供同模块测试读取 TaskHandle 的内部 state owner。 */
    class TaskHandleTestAccess final
    {
    public:
        [[nodiscard]] static auto State(const TaskHandle &Handle) noexcept
            -> const std::shared_ptr<TaskState> &
        {
            return Handle.State_;
        }
    };
}
