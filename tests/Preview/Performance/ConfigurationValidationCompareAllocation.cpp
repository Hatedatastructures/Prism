/**
 * @file ConfigurationValidationCompareAllocation.cpp
 * @brief 配置校验对照工具的进程级分配统计和全局 new 所有者。
 */

#include "ConfigurationValidationCompareAllocation.hpp"

#include <atomic>
#include <cstdlib>
#include <new>

#if defined(_WIN32)
#    include <malloc.h>
#endif

namespace Preview::Application::Configuration::Perf::Allocation
{

    auto Allocate(const std::size_t Size) -> void *
    {
        const auto ActualSize = Size == 0 ? std::size_t{1} : Size;
        auto *Memory = std::malloc(ActualSize);
        if (Memory == nullptr)
        {
            throw std::bad_alloc{};
        }
        if (Tracking.load(std::memory_order_relaxed))
        {
            AllocationCount.fetch_add(1, std::memory_order_relaxed);
            AllocationBytes.fetch_add(static_cast<std::uint64_t>(Size),
                                      std::memory_order_relaxed);
        }
        return Memory;
    }

    auto AllocateAligned(const std::size_t Size, const std::size_t Alignment) -> void *
    {
        const auto ActualSize = Size == 0 ? std::size_t{1} : Size;
        void *Memory = nullptr;
#if defined(_WIN32)
        Memory = _aligned_malloc(ActualSize, Alignment);
#else
        const auto RoundedSize =
            ((ActualSize + Alignment - 1U) / Alignment) * Alignment;
        Memory = std::aligned_alloc(Alignment, RoundedSize);
#endif
        if (Memory == nullptr)
        {
            throw std::bad_alloc{};
        }
        if (Tracking.load(std::memory_order_relaxed))
        {
            AlignedAllocationCount.fetch_add(1, std::memory_order_relaxed);
            AlignedAllocationBytes.fetch_add(static_cast<std::uint64_t>(Size),
                                             std::memory_order_relaxed);
        }
        return Memory;
    }

    auto ReleaseAligned(void *Memory) noexcept -> void
    {
#if defined(_WIN32)
        _aligned_free(Memory);
#else
        std::free(Memory);
#endif
    }

} // namespace Preview::Application::Configuration::Perf::Allocation

auto operator new(const std::size_t Size) -> void *
{
    return Preview::Application::Configuration::Perf::Allocation::Allocate(Size);
}

auto operator new[](const std::size_t Size) -> void *
{
    return Preview::Application::Configuration::Perf::Allocation::Allocate(Size);
}

auto operator new(const std::size_t Size, const std::nothrow_t &) noexcept -> void *
{
    try
    {
        return ::operator new(Size);
    }
    catch (...)
    {
        return nullptr;
    }
}

auto operator new[](const std::size_t Size, const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Tag);
}

auto operator new(const std::size_t Size, const std::align_val_t Alignment) -> void *
{
    return Preview::Application::Configuration::Perf::Allocation::AllocateAligned(
        Size, static_cast<std::size_t>(Alignment));
}

auto operator new[](const std::size_t Size, const std::align_val_t Alignment) -> void *
{
    return ::operator new(Size, Alignment);
}

auto operator new(const std::size_t Size, const std::align_val_t Alignment,
                  const std::nothrow_t &) noexcept -> void *
{
    try
    {
        return Preview::Application::Configuration::Perf::Allocation::AllocateAligned(
            Size, static_cast<std::size_t>(Alignment));
    }
    catch (...)
    {
        return nullptr;
    }
}

auto operator new[](const std::size_t Size, const std::align_val_t Alignment,
                    const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Alignment, Tag);
}

auto operator delete(void *Memory) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory) noexcept -> void
{
    std::free(Memory);
}

auto operator delete(void *Memory, const std::size_t) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory, const std::size_t) noexcept -> void
{
    std::free(Memory);
}

auto operator delete(void *Memory, const std::nothrow_t &) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory, const std::nothrow_t &) noexcept -> void
{
    std::free(Memory);
}

auto operator delete(void *Memory, const std::align_val_t) noexcept -> void
{
    Preview::Application::Configuration::Perf::Allocation::ReleaseAligned(Memory);
}

auto operator delete[](void *Memory, const std::align_val_t) noexcept -> void
{
    Preview::Application::Configuration::Perf::Allocation::ReleaseAligned(Memory);
}

auto operator delete(void *Memory, const std::size_t,
                     const std::align_val_t) noexcept -> void
{
    Preview::Application::Configuration::Perf::Allocation::ReleaseAligned(Memory);
}

auto operator delete[](void *Memory, const std::size_t,
                       const std::align_val_t) noexcept -> void
{
    Preview::Application::Configuration::Perf::Allocation::ReleaseAligned(Memory);
}
