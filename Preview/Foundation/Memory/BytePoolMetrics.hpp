/**
 * @file BytePoolMetrics.hpp
 * @brief 字节池的独立值快照。
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace Preview::Memory
{
    /**
     * @brief 字节池容量、租约计数及观察到的峰值。
     * @details 当前占用和可用量由位图逐字观察；并发变化时字段不构成同一时刻的原子快照。
     *          分配/释放计数只统计成功发放与归还的块租约，不包含失败的准入请求。
     *          峰值使用固定次数原子更新，在高并发竞争下可能低估短暂峰值；快照不低于本次观察到的占用量。
     *          当前占用观察为 O(ceil(块数 / 64))，应仅在冷快照边界调用。
     */
    struct BytePoolMetrics final
    {
        std::size_t CapacityBytes{0};
        std::size_t UsedBytes{0};
        std::size_t AvailableBytes{0};
        std::uint64_t AllocationCount{0};
        std::uint64_t ReleaseCount{0};
        std::size_t PeakUsedBytes{0};
    };
}
