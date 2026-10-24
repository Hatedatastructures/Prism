/**
 * @file ResourceMemorySnapshot.hpp
 * @brief 进程与 worker 可序列化的 owner 内存值快照。
 */
#pragma once

#include <Prism/Foundation/Memory/BytePoolModels.hpp>
#include <Prism/Foundation/Memory/MemoryAllocationSnapshot.hpp>

namespace Prism::Resource
{
    /** @brief 单个 ProcessResources 或 WorkerResources 的 Prism-owned 内存计数。 */
    struct ResourceMemorySnapshot final
    {
        Prism::Memory::MemoryAllocationSnapshot Pmr;
        Prism::Memory::BytePoolMetrics BytePool;
    };
}
