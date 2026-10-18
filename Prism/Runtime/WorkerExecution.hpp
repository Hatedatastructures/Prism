/** @file WorkerExecution.hpp @brief Worker 上下文执行期间的本地资源作用域。 */
#pragma once

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Resource/WorkerResources.hpp>

#include <cstddef>

namespace Prism::Runtime::Detail
{
    /** @brief 在唯一 worker 线程作用域运行 io_context，覆盖所有调度回调分配。 */
    inline auto RunWorkerContext(Prism::Resource::WorkerResources &Resources) -> void
    {
        Prism::Memory::ResourceScope Scope(Resources.MemoryResource);
        Resources.IoContext.run();
    }

    /** @brief 同步泵只在调用栈内设置 worker 资源，不跨协程挂起。 */
    [[nodiscard]] inline auto PumpWorkerContext(Prism::Resource::WorkerResources &Resources)
        -> std::size_t
    {
        Prism::Memory::ResourceScope Scope(Resources.MemoryResource);
        return Resources.IoContext.poll();
    }
}
