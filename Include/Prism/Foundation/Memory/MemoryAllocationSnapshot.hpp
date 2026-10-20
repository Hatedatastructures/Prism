/**
 * @file MemoryAllocationSnapshot.hpp
 * @brief Prism PMR 分配跟踪器的独立值快照。
 */
#pragma once

#include <cstdint>

namespace Prism::Memory
{
    /**
     * @brief 通过指定 PMR 资源发生的请求字节与调用计数。
     * @details 字节数反映尚未收到 deallocate 的调用方请求量，不是堆、池或进程物理页的实际占用。
     *          计数仅覆盖经过对应 TrackingResource 的 Prism PMR 请求。
     */
    struct MemoryAllocationSnapshot final
    {
        std::uint64_t CurrentBytes{0};
        std::uint64_t PeakBytes{0};
        std::uint64_t AllocationCount{0};
        std::uint64_t DeallocationCount{0};
    };
}
