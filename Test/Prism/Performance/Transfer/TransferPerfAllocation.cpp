/**
 * @file TransferPerfAllocation.cpp
 * @brief TransferPerf 的全局 allocation hook owner。
 */

#include "TransferPerf.hpp"

namespace TransferPerfAllocation
{
    inline auto Allocate(const std::size_t Bytes, const std::size_t Alignment) -> void *
    {
        const auto Size = Bytes == 0 ? std::size_t{1} : Bytes;
        if (Alignment <= alignof(std::max_align_t))
        {
            return std::malloc(Size);
        }
#ifdef _WIN32
        return _aligned_malloc(Size, Alignment);
#else
        if (Size > (std::numeric_limits<std::size_t>::max)() - (Alignment - 1U))
        {
            return nullptr;
        }
        const auto Rounded = (Size + Alignment - 1U) / Alignment * Alignment;
        return std::aligned_alloc(Alignment, Rounded);
#endif
    }

    inline auto Deallocate(void *Pointer, const std::size_t Alignment) noexcept -> void
    {
        if (Alignment <= alignof(std::max_align_t))
        {
            std::free(Pointer);
            return;
        }
#ifdef _WIN32
        _aligned_free(Pointer);
#else
        std::free(Pointer);
#endif
    }

    inline auto RecordAllocation(const bool Aligned, const std::size_t Bytes) noexcept -> void
    {
        if (!State.Active.load(std::memory_order_relaxed))
        {
            return;
        }
        if (Aligned)
        {
            State.AlignedAllocations.fetch_add(1, std::memory_order_relaxed);
            State.AlignedBytes.fetch_add(Bytes, std::memory_order_relaxed);
        }
        else
        {
            State.OrdinaryAllocations.fetch_add(1, std::memory_order_relaxed);
            State.OrdinaryBytes.fetch_add(Bytes, std::memory_order_relaxed);
        }
    }

    inline auto RecordFree(const bool Aligned) noexcept -> void
    {
        if (!State.Active.load(std::memory_order_relaxed))
        {
            return;
        }
        if (Aligned)
        {
            State.AlignedFrees.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            State.OrdinaryFrees.fetch_add(1, std::memory_order_relaxed);
        }
    }

}

auto operator new(const std::size_t Bytes) -> void *
{
    if (auto *Pointer = TransferPerfAllocation::Allocate(Bytes, alignof(std::max_align_t)))
    {
        TransferPerfAllocation::RecordAllocation(false, Bytes);
        return Pointer;
    }
    throw std::bad_alloc{};
}

auto operator new[](const std::size_t Bytes) -> void *
{
    return ::operator new(Bytes);
}

auto operator new(const std::size_t Bytes, const std::nothrow_t &) noexcept -> void *
{
    auto *Pointer = TransferPerfAllocation::Allocate(Bytes, alignof(std::max_align_t));
    if (Pointer)
    {
        TransferPerfAllocation::RecordAllocation(false, Bytes);
    }
    return Pointer;
}

auto operator new[](const std::size_t Bytes, const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Bytes, Tag);
}

auto operator new(const std::size_t Bytes, const std::align_val_t Alignment) -> void *
{
    const auto Value = static_cast<std::size_t>(Alignment);
    if (auto *Pointer = TransferPerfAllocation::Allocate(Bytes, Value))
    {
        TransferPerfAllocation::RecordAllocation(true, Bytes);
        return Pointer;
    }
    throw std::bad_alloc{};
}

auto operator new[](const std::size_t Bytes, const std::align_val_t Alignment) -> void *
{
    return ::operator new(Bytes, Alignment);
}

auto operator new(
    const std::size_t Bytes,
    const std::align_val_t Alignment,
    const std::nothrow_t &) noexcept -> void *
{
    const auto Value = static_cast<std::size_t>(Alignment);
    auto *Pointer = TransferPerfAllocation::Allocate(Bytes, Value);
    if (Pointer)
    {
        TransferPerfAllocation::RecordAllocation(true, Bytes);
    }
    return Pointer;
}

auto operator new[](
    const std::size_t Bytes,
    const std::align_val_t Alignment,
    const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Bytes, Alignment, Tag);
}

auto operator delete(void *Pointer) noexcept -> void
{
    TransferPerfAllocation::RecordFree(false);
    TransferPerfAllocation::Deallocate(Pointer, alignof(std::max_align_t));
}

auto operator delete[](void *Pointer) noexcept -> void
{
    ::operator delete(Pointer);
}

auto operator delete(void *Pointer, const std::size_t) noexcept -> void
{
    ::operator delete(Pointer);
}

auto operator delete[](void *Pointer, const std::size_t) noexcept -> void
{
    ::operator delete(Pointer);
}

auto operator delete(void *Pointer, const std::align_val_t Alignment) noexcept -> void
{
    TransferPerfAllocation::RecordFree(true);
    TransferPerfAllocation::Deallocate(Pointer, static_cast<std::size_t>(Alignment));
}

auto operator delete[](void *Pointer, const std::align_val_t Alignment) noexcept -> void
{
    ::operator delete(Pointer, Alignment);
}

auto operator delete(
    void *Pointer,
    const std::size_t,
    const std::align_val_t Alignment) noexcept -> void
{
    ::operator delete(Pointer, Alignment);
}

auto operator delete[](
    void *Pointer,
    const std::size_t,
    const std::align_val_t Alignment) noexcept -> void
{
    ::operator delete(Pointer, Alignment);
}

auto operator delete(void *Pointer, const std::nothrow_t &) noexcept -> void
{
    ::operator delete(Pointer);
}

auto operator delete[](void *Pointer, const std::nothrow_t &) noexcept -> void
{
    ::operator delete(Pointer);
}

auto operator delete(
    void *Pointer,
    const std::align_val_t Alignment,
    const std::nothrow_t &) noexcept -> void
{
    ::operator delete(Pointer, Alignment);
}

auto operator delete[](
    void *Pointer,
    const std::align_val_t Alignment,
    const std::nothrow_t &) noexcept -> void
{
    ::operator delete(Pointer, Alignment);
}

auto operator delete(
    void *Pointer,
    const std::size_t,
    const std::nothrow_t &) noexcept -> void
{
    ::operator delete(Pointer);
}

auto operator delete[](
    void *Pointer,
    const std::size_t,
    const std::nothrow_t &) noexcept -> void
{
    ::operator delete(Pointer);
}

