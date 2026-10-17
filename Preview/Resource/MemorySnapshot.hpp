/**
 * @file MemorySnapshot.hpp
 * @brief 进程与 worker 可序列化的 owner 内存值快照。
 */
#pragma once

#include <Preview/Foundation/Memory/BytePoolMetrics.hpp>
#include <Preview/Foundation/Memory/MemoryAllocationSnapshot.hpp>

namespace Preview::Resource
{
    /** @brief 单个 ProcessResources 或 WorkerResources 的 Prism-owned 内存计数。 */
    struct ResourceMemorySnapshot final
    {
        Preview::Memory::MemoryAllocationSnapshot Pmr;
        Preview::Memory::BytePoolMetrics BytePool;
    };
}
