/**
 * @file TrackingResource.hpp
 * @brief 以固定原子计数跟踪 Prism PMR 请求的透明资源包装器。
 */
#pragma once

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/MemoryAllocationSnapshot.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory_resource>

namespace Preview::Memory
{
    /**
     * @brief 转发到上游资源并记录仍未释放的 PMR 请求。
     * @details 跟踪器不拥有上游资源；上游须比本对象活得更久。
     *          分配/释放不加锁、不分配内存、不做 I/O，峰值更新最多执行一次 CAS。
     *          峰值在多线程竞争时可能低估瞬时高点；快照把已观察的当前值纳入峰值下限。
     *          调用方请求字节和调用次数不表示池的底层保留量，也不覆盖绕过本对象的分配。
     */
    class TrackingResource final : public std::pmr::memory_resource
    {
    public:
        static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

        explicit TrackingResource(ResourcePointer Upstream = std::pmr::get_default_resource()) noexcept
            : Upstream_(Upstream ? Upstream : std::pmr::get_default_resource())
        {
        }

        TrackingResource(const TrackingResource&) = delete;
        auto operator=(const TrackingResource&) -> TrackingResource& = delete;
        TrackingResource(TrackingResource&&) = delete;
        auto operator=(TrackingResource&&) -> TrackingResource& = delete;

        /** @brief 返回拥有型计数快照，不分配且不访问上游资源。 */
        [[nodiscard]] auto Snapshot() const noexcept -> MemoryAllocationSnapshot
        {
            const auto Current = CurrentBytes_.load(std::memory_order_relaxed);
            const auto RecordedPeak = PeakBytes_.load(std::memory_order_relaxed);
            return MemoryAllocationSnapshot{Current, std::max(Current, RecordedPeak),
                AllocationCount_.load(std::memory_order_relaxed),
                DeallocationCount_.load(std::memory_order_relaxed)};
        }

    protected:
        auto do_allocate(const std::size_t Bytes, const std::size_t Alignment) -> void* override
        {
            auto* const Result = Upstream_->allocate(Bytes, Alignment);
            const auto Current = CurrentBytes_.fetch_add(Bytes, std::memory_order_relaxed) + Bytes;
            AllocationCount_.fetch_add(1, std::memory_order_relaxed);
            RecordPeak(Current);
            return Result;
        }

        auto do_deallocate(void* Pointer, const std::size_t Bytes, const std::size_t Alignment) -> void override
        {
            Upstream_->deallocate(Pointer, Bytes, Alignment);
            CurrentBytes_.fetch_sub(Bytes, std::memory_order_relaxed);
            DeallocationCount_.fetch_add(1, std::memory_order_relaxed);
        }

        [[nodiscard]] auto do_is_equal(const std::pmr::memory_resource& Other) const noexcept -> bool override
        {
            return this == &Other;
        }

    private:
        auto RecordPeak(const std::uint64_t Current) noexcept -> void
        {
            auto Peak = PeakBytes_.load(std::memory_order_relaxed);
            if (Current > Peak)
            {
                (void)PeakBytes_.compare_exchange_strong(
                    Peak, Current, std::memory_order_relaxed, std::memory_order_relaxed);
            }
        }

        ResourcePointer Upstream_;
        std::atomic<std::uint64_t> CurrentBytes_{0};
        std::atomic<std::uint64_t> PeakBytes_{0};
        std::atomic<std::uint64_t> AllocationCount_{0};
        std::atomic<std::uint64_t> DeallocationCount_{0};
    };
}
