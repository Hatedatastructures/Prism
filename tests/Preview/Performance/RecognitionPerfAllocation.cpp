/**
 * @file RecognitionPerfAllocation.cpp
 * @brief RecognitionPerf 的全局 allocation hook owner。
 */

#include "RecognitionPerf.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    using Preview::Recognition::Perf::AllocationCount;
    using Preview::Recognition::Perf::AllocationBytes;
    using Preview::Recognition::Perf::AlignedAllocationCount;
    using Preview::Recognition::Perf::AlignedAllocationBytes;
    using Preview::Recognition::Perf::AllocationMeasurementEnabled;

    auto RecordAllocation(void *Pointer, std::size_t Size) -> void *
    {
        if (Pointer != nullptr && AllocationMeasurementEnabled.load(std::memory_order_relaxed))
        {
            AllocationCount.fetch_add(1, std::memory_order_relaxed);
            AllocationBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        return Pointer;
    }

    auto AllocateAligned(std::size_t Size, std::size_t Alignment) -> void *
    {
        auto Requested = Size;
        if (Requested == 0)
        {
            Requested = 1;
        }
        if (Alignment == 0 || Requested > (std::numeric_limits<std::size_t>::max)() - (Alignment - 1U))
        {
            return nullptr;
        }
        const auto Rounded = (Requested + Alignment - 1U) / Alignment * Alignment;
#ifdef _WIN32
        auto *Pointer = _aligned_malloc(Rounded, Alignment);
#else
        auto *Pointer = std::aligned_alloc(Alignment, Rounded);
#endif
        if (Pointer != nullptr && AllocationMeasurementEnabled.load(std::memory_order_relaxed))
        {
            AlignedAllocationCount.fetch_add(1, std::memory_order_relaxed);
            AlignedAllocationBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        return Pointer;
    }

    auto ReleaseAligned(void *Pointer) noexcept -> void
    {
#ifdef _WIN32
        _aligned_free(Pointer);
#else
        std::free(Pointer);
#endif
    }

    [[nodiscard]] auto ValidateAllocationInstrumentation() -> bool
    {
        constexpr auto Alignment = std::align_val_t{64};
        void *Ordinary = nullptr;
        void *OrdinaryArray = nullptr;
        void *OrdinaryNoThrow = nullptr;
        void *OrdinaryArrayNoThrow = nullptr;
        void *Aligned = nullptr;
        void *AlignedArray = nullptr;
        void *AlignedNoThrow = nullptr;
        void *AlignedArrayNoThrow = nullptr;
        bool Success = true;

        Preview::Recognition::Perf::ResetAllocationCounters();
        AllocationMeasurementEnabled.store(true, std::memory_order_release);
        try
        {
            Ordinary = ::operator new(17U);
            OrdinaryArray = ::operator new[](19U);
            OrdinaryNoThrow = ::operator new(23U, std::nothrow);
            OrdinaryArrayNoThrow = ::operator new[](29U, std::nothrow);
            Aligned = ::operator new(31U, Alignment);
            AlignedArray = ::operator new[](37U, Alignment);
            AlignedNoThrow = ::operator new(41U, Alignment, std::nothrow);
            AlignedArrayNoThrow = ::operator new[](43U, Alignment, std::nothrow);
        }
        catch (...)
        {
            Success = false;
        }
        AllocationMeasurementEnabled.store(false, std::memory_order_release);
        ::operator delete(Ordinary);
        ::operator delete[](OrdinaryArray);
        ::operator delete(OrdinaryNoThrow);
        ::operator delete[](OrdinaryArrayNoThrow);
        ::operator delete(Aligned, Alignment);
        ::operator delete[](AlignedArray, Alignment);
        ::operator delete(AlignedNoThrow, Alignment);
        ::operator delete[](AlignedArrayNoThrow, Alignment);

        const auto Snapshot = Preview::Recognition::Perf::ReadAllocationCounters();
        const auto AlignedPointersValid =
            Aligned != nullptr && AlignedArray != nullptr && AlignedNoThrow != nullptr &&
            AlignedArrayNoThrow != nullptr &&
            reinterpret_cast<std::uintptr_t>(Aligned) % static_cast<std::size_t>(Alignment) == 0U &&
            reinterpret_cast<std::uintptr_t>(AlignedArray) % static_cast<std::size_t>(Alignment) == 0U &&
            reinterpret_cast<std::uintptr_t>(AlignedNoThrow) % static_cast<std::size_t>(Alignment) == 0U &&
            reinterpret_cast<std::uintptr_t>(AlignedArrayNoThrow) % static_cast<std::size_t>(Alignment) == 0U;
        const auto Valid = Success && Ordinary != nullptr && OrdinaryArray != nullptr &&
            OrdinaryNoThrow != nullptr && OrdinaryArrayNoThrow != nullptr &&
            AlignedPointersValid && Snapshot.Count == 4U && Snapshot.Bytes == 88U &&
            Snapshot.AlignedCount == 4U && Snapshot.AlignedBytes == 152U;
        AllocationMeasurementEnabled.store(true, std::memory_order_release);
        if (!Valid)
        {
            std::cerr << "[FAIL] recognition allocation preflight ordinary="
                      << Snapshot.Count << "/" << Snapshot.Bytes << " aligned="
                      << Snapshot.AlignedCount << "/" << Snapshot.AlignedBytes << "\n";
        }
        return Valid;
    }


}

auto operator new(std::size_t Size) -> void *
{
    auto AllocationSize = Size;
    if (AllocationSize == 0)
    {
        AllocationSize = 1;
    }
    if (auto *Pointer = RecordAllocation(std::malloc(AllocationSize), Size))
    {
        return Pointer;
    }
    throw std::bad_alloc();
}

auto operator new[](std::size_t Size) -> void *
{
    return ::operator new(Size);
}

auto operator new(std::size_t Size, const std::nothrow_t &) noexcept -> void *
{
    auto AllocationSize = Size;
    if (AllocationSize == 0)
    {
        AllocationSize = 1;
    }
    return RecordAllocation(std::malloc(AllocationSize), Size);
}

auto operator new[](std::size_t Size, const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Tag);
}

auto operator new(std::size_t Size, std::align_val_t Alignment) -> void *
{
    if (auto *Pointer = AllocateAligned(Size, static_cast<std::size_t>(Alignment)))
    {
        return Pointer;
    }
    throw std::bad_alloc();
}

auto operator new[](std::size_t Size, std::align_val_t Alignment) -> void *
{
    return ::operator new(Size, Alignment);
}

auto operator new(
    std::size_t Size,
    std::align_val_t Alignment,
    const std::nothrow_t &) noexcept -> void *
{
    return AllocateAligned(Size, static_cast<std::size_t>(Alignment));
}

auto operator new[](
    std::size_t Size,
    std::align_val_t Alignment,
    const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Alignment, Tag);
}

auto operator delete(void *Pointer) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete[](void *Pointer) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete(void *Pointer, std::size_t) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete[](void *Pointer, std::size_t) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete(void *Pointer, const std::nothrow_t &) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete[](void *Pointer, const std::nothrow_t &) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete(void *Pointer, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete[](void *Pointer, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete(void *Pointer, std::size_t, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete[](void *Pointer, std::size_t, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete(void *Pointer, std::align_val_t, const std::nothrow_t &) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete[](void *Pointer, std::align_val_t, const std::nothrow_t &) noexcept -> void
{
    ReleaseAligned(Pointer);
}

namespace Preview::Recognition::Perf
{
    [[nodiscard]] auto ValidateAllocationInstrumentation() -> bool { return ::ValidateAllocationInstrumentation(); }
}
