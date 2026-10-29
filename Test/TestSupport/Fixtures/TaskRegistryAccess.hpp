/**
 * @file TaskRegistryAccess.hpp
 * @brief 既有任务身份边界用例的私有准入夹具。
 */
#pragma once

#include <Prism/Lifecycle/Task/Registry.hpp>
#include <cstdint>

namespace Prism::Lifecycle
{
    /**
     * @brief 仅测试源可包含的 friend 访问，不恢复生产指定 TaskId 入口。
     * @details 夹具必须独占进程身份序列，待本场景全部任务/drain退栈后恢复。
     *          并发 lane 只能在固定种子之后分配，不能并发改变序列。
     */
    class TaskRegistryTestAccess final
    {
    public:
        /** @brief 在原场景边界交换下一身份；0保留耗尽输入，返回原状态供最终恢复。 */
        [[nodiscard]] static auto ExchangeNextId(const std::uint64_t Next) noexcept -> std::uint64_t
        {
            return TaskRegistry::NextTaskId_.exchange(Next);
        }
    };
}
