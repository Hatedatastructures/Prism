/** @file WorkerResources.cpp @brief worker 通用执行上下文与内存资源实现。 */
#include <Prism/Resource/WorkerResources.hpp>

#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Resource/Detail/WorkerMemoryResourceService.hpp>

#include <memory>

namespace Prism::Resource
{
    WorkerResources::WorkerResources() : WorkerResources(Options{})
    {
    }

    WorkerResources::WorkerResources(Options Value)
        : Process(Value.Process), Id(Value.Id), Generation(Value.Generation),
          Execution(Prism::Executor::ContextOwner::Create()),
          AllocationMetrics(AttachMemoryMetrics(Execution)),
          MemoryResource(&AllocationMetrics->Tracker()),
          Bytes(std::make_shared<Prism::Memory::BytePool>(Value.Bytes))
    {
    }

    WorkerResources::~WorkerResources() noexcept = default;

    auto WorkerResources::MemorySnapshot() const noexcept -> ResourceMemorySnapshot
    {
        return {AllocationMetrics->Snapshot(),
            Bytes ? Bytes->Snapshot() : Prism::Memory::BytePoolMetrics{}};
    }

    auto WorkerResources::AttachMemoryMetrics(
        const std::shared_ptr<Prism::Executor::ContextOwner>& Owner)
        -> Prism::Resource::WorkerMemoryResourceService*
    {
        return Prism::Resource::WorkerMemoryResourceService::Attach(*Owner);
    }
}
