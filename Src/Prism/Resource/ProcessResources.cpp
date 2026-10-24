/** @file ProcessResources.cpp @brief 进程级池、停止门与内存快照实现。 */
#include <Prism/Resource/ProcessResources.hpp>

#include <atomic>
#include <memory>

namespace Prism::Resource
{
    ProcessResources::ProcessResources() : ProcessResources(Options{}) {}

    ProcessResources::ProcessResources(Options Value)
        : Id(Value.Id), Generation(Value.Generation), AllocationMetrics(Value.MemoryResource),
          MemoryResource(&AllocationMetrics), Bytes(std::make_shared<Prism::Memory::BytePool>()) {}

    auto ProcessResources::BeginStop() noexcept -> bool
    {
        return Stopping.exchange(true, std::memory_order_acq_rel) == false;
    }

    auto ProcessResources::IsStopping() const noexcept -> bool
    {
        return Stopping.load(std::memory_order_acquire);
    }

    auto ProcessResources::MemorySnapshot() const noexcept -> ResourceMemorySnapshot
    {
        return {AllocationMetrics.Snapshot(),
            Bytes ? Bytes->Snapshot() : Prism::Memory::BytePoolMetrics{}};
    }
}
