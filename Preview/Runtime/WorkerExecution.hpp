/** @file WorkerExecution.hpp @brief Worker 上下文执行期间的本地资源作用域。 */
#pragma once

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Resource/WorkerResources.hpp>

#include <cstddef>

namespace Preview::Runtime::Detail
{
    /** @brief 在唯一 worker 线程作用域运行 io_context，覆盖所有调度回调分配。 */
    inline auto RunWorkerContext(Preview::Resource::WorkerResources &Resources) -> void
    {
        Preview::Memory::ResourceScope Scope(Resources.MemoryResource);
        Resources.IoContext.run();
    }

    /** @brief 同步泵只在调用栈内设置 worker 资源，不跨协程挂起。 */
    [[nodiscard]] inline auto PumpWorkerContext(Preview::Resource::WorkerResources &Resources)
        -> std::size_t
    {
        Preview::Memory::ResourceScope Scope(Resources.MemoryResource);
        return Resources.IoContext.poll();
    }
}
