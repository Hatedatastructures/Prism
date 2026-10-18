/**
 * @file ProtocolTransferBenchAllocation.cpp
 * @brief 协议传输基准的全局 allocation hook owner。
 */

#include "ProtocolTransferBench.hpp"

namespace ProtocolBenchAllocation
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

    inline auto Free(void *Pointer, const std::size_t Alignment) noexcept -> void
    {
#ifdef _WIN32
        if (Alignment > alignof(std::max_align_t))
        {
            _aligned_free(Pointer);
            return;
        }
#endif
        std::free(Pointer);
    }

    inline auto Record(const bool Aligned, const std::size_t Bytes) noexcept -> void
    {
        if (!Active.load(std::memory_order_relaxed))
        {
            return;
        }
        if (Aligned)
        {
            AlignedAllocations.fetch_add(1, std::memory_order_relaxed);
            AlignedBytes.fetch_add(Bytes, std::memory_order_relaxed);
        }
        else
        {
            OrdinaryAllocations.fetch_add(1, std::memory_order_relaxed);
            OrdinaryBytes.fetch_add(Bytes, std::memory_order_relaxed);
        }
    }

}

auto operator new(const std::size_t Bytes) -> void *
{
    if (auto *Pointer = ProtocolBenchAllocation::Allocate(Bytes, alignof(std::max_align_t)))
    {
        ProtocolBenchAllocation::Record(false, Bytes);
        return Pointer;
    }
    throw std::bad_alloc{};
}

auto operator new[](const std::size_t Bytes) -> void *
{
    return ::operator new(Bytes);
}

auto operator new(const std::size_t Bytes, const std::align_val_t Alignment) -> void *
{
    const auto Value = static_cast<std::size_t>(Alignment);
    if (auto *Pointer = ProtocolBenchAllocation::Allocate(Bytes, Value))
    {
        ProtocolBenchAllocation::Record(true, Bytes);
        return Pointer;
    }
    throw std::bad_alloc{};
}

auto operator new[](const std::size_t Bytes, const std::align_val_t Alignment) -> void *
{
    return ::operator new(Bytes, Alignment);
}

auto operator new(const std::size_t Bytes, const std::nothrow_t &) noexcept -> void *
{
    if (auto *Pointer = ProtocolBenchAllocation::Allocate(Bytes, alignof(std::max_align_t)))
    {
        ProtocolBenchAllocation::Record(false, Bytes);
        return Pointer;
    }
    return nullptr;
}

auto operator new[](const std::size_t Bytes, const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Bytes, Tag);
}

auto operator new(
    const std::size_t Bytes,
    const std::align_val_t Alignment,
    const std::nothrow_t &) noexcept -> void *
{
    if (auto *Pointer = ProtocolBenchAllocation::Allocate(
            Bytes, static_cast<std::size_t>(Alignment)))
    {
        ProtocolBenchAllocation::Record(true, Bytes);
        return Pointer;
    }
    return nullptr;
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
    ProtocolBenchAllocation::Free(Pointer, alignof(std::max_align_t));
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
    ProtocolBenchAllocation::Free(Pointer, static_cast<std::size_t>(Alignment));
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


