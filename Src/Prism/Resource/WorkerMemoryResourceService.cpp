/** @file WorkerMemoryResourceService.cpp @brief worker 内存跟踪 service 生命周期实现。 */
#include <Prism/Resource/Detail/WorkerMemoryResourceService.hpp>

#include <Prism/Foundation/Executor/ContextOwner.hpp>

namespace Prism::Resource
{
    WorkerMemoryResourceService::WorkerMemoryResourceService(
        Net::execution_context& Context, Prism::Memory::ResourcePointer Upstream)
        : service(Context), Tracker_(Upstream) {}

    auto WorkerMemoryResourceService::Attach(Prism::Executor::ContextOwner& Owner)
        -> WorkerMemoryResourceService*
    {
        auto* Service = new WorkerMemoryResourceService(Owner.Io, &Owner.Pool);
        Net::add_service<WorkerMemoryResourceService>(Owner.Io, Service);
        return Service;
    }

    auto WorkerMemoryResourceService::shutdown() -> void
    {
    }
}
