/**
 * @file MuxPerfAllocation.cpp
 * @brief 每个 Mux 性能可执行文件唯一的全局分配替换。
 * @details 普通、数组、nothrow 与 aligned 路径共享同一窗口统计，禁止 inline 替换。
 */
#include "MuxPerfAllocation.hpp"

void *operator new(const std::size_t Size)
{
    if (auto *Value = PrismMuxPerfAllocation::Allocate(Size, 0U))
    {
        PrismMuxPerfAllocation::Record(Size, false);
        return Value;
    }
    throw std::bad_alloc();
}

void *operator new[](const std::size_t Size)
{
    return ::operator new(Size);
}

void *operator new(const std::size_t Size, const std::nothrow_t &) noexcept
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

void *operator new[](const std::size_t Size, const std::nothrow_t &Tag) noexcept
{
    return ::operator new(Size, Tag);
}

void *operator new(const std::size_t Size, const std::align_val_t Alignment)
{
    const auto Value = static_cast<std::size_t>(Alignment);
    if (auto *Memory = PrismMuxPerfAllocation::Allocate(Size, Value))
    {
        PrismMuxPerfAllocation::Record(Size, true);
        return Memory;
    }
    throw std::bad_alloc();
}

void *operator new[](const std::size_t Size, const std::align_val_t Alignment)
{
    return ::operator new(Size, Alignment);
}

void *operator new(const std::size_t Size, const std::align_val_t Alignment,
                          const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new(Size, Alignment);
    }
    catch (...)
    {
        return nullptr;
    }
}

void *operator new[](const std::size_t Size, const std::align_val_t Alignment,
                            const std::nothrow_t &Tag) noexcept
{
    return ::operator new(Size, Alignment, Tag);
}

void operator delete(void *Value) noexcept { std::free(Value); }
void operator delete[](void *Value) noexcept { std::free(Value); }
void operator delete(void *Value, const std::size_t) noexcept { std::free(Value); }
void operator delete[](void *Value, const std::size_t) noexcept { std::free(Value); }
void operator delete(void *Value, const std::align_val_t) noexcept
{
    PrismMuxPerfAllocation::FreeAligned(Value);
}
void operator delete[](void *Value, const std::align_val_t) noexcept
{
    PrismMuxPerfAllocation::FreeAligned(Value);
}
void operator delete(void *Value, const std::size_t, const std::align_val_t) noexcept
{
    PrismMuxPerfAllocation::FreeAligned(Value);
}
void operator delete[](void *Value, const std::size_t, const std::align_val_t) noexcept
{
    PrismMuxPerfAllocation::FreeAligned(Value);
}
void operator delete(void *Value, const std::nothrow_t &) noexcept { std::free(Value); }
void operator delete[](void *Value, const std::nothrow_t &) noexcept { std::free(Value); }
void operator delete(void *Value, const std::align_val_t, const std::nothrow_t &) noexcept
{
    PrismMuxPerfAllocation::FreeAligned(Value);
}
void operator delete[](void *Value, const std::align_val_t, const std::nothrow_t &) noexcept
{
    PrismMuxPerfAllocation::FreeAligned(Value);
}
