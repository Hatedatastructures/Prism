/**
 * @file TrackingResource.cpp
 * @brief PMR 分配跟踪器运行实现。
 */
#include <Prism/Foundation/Memory/TrackingResource.hpp>

namespace Prism::Memory
{
    TrackingResource::TrackingResource(const ResourcePointer Upstream) noexcept
        : Upstream_(Upstream ? Upstream : std::pmr::get_default_resource())
    {
    }

    auto TrackingResource::do_allocate(const std::size_t Bytes, const std::size_t Alignment) -> void*
    {
        auto* const Result = Upstream_->allocate(Bytes, Alignment);
        const auto Current = CurrentBytes_.fetch_add(Bytes, std::memory_order_relaxed) + Bytes;
        AllocationCount_.fetch_add(1, std::memory_order_relaxed);
        RecordPeak(Current);
        return Result;
    }

    auto TrackingResource::do_deallocate(
        void* Pointer, const std::size_t Bytes, const std::size_t Alignment) -> void
    {
        Upstream_->deallocate(Pointer, Bytes, Alignment);
        CurrentBytes_.fetch_sub(Bytes, std::memory_order_relaxed);
        DeallocationCount_.fetch_add(1, std::memory_order_relaxed);
    }

    auto TrackingResource::RecordPeak(const std::uint64_t Current) noexcept -> void
    {
        auto Peak = PeakBytes_.load(std::memory_order_relaxed);
        if (Current > Peak)
        {
            (void)PeakBytes_.compare_exchange_strong(
                Peak, Current, std::memory_order_relaxed, std::memory_order_relaxed);
        }
    }
}
