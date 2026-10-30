/**
 * @file BytePoolModels.hpp
 * @brief 字节池创建配置与只读容量指标。
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace Prism::Memory
{
    /**
     * @brief 字节池当前容量、配置上限、租约计数及观察到的峰值。
     * @details CapacityBytes 是当前已经分配的真实存储，不是配置允许的最大容量。
     *          当前占用和可用量由位图逐字观察；并发变化时字段不构成同一时刻的原子快照。
     *          分配/释放计数只统计成功发放与归还的块租约，不包含失败的准入请求。
     *          峰值使用固定次数原子更新，在高并发竞争下可能低估短暂峰值；快照不低于本次观察到的占用量。
     *          当前占用观察为 O(ceil(最大块数 / 64))，应仅在冷快照边界调用。
     */
    struct BytePoolMetrics final
    {
        std::size_t CapacityBytes{0};
        std::size_t UsedBytes{0};
        std::size_t AvailableBytes{0};
        std::uint64_t AllocationCount{0};
        std::uint64_t ReleaseCount{0};
        std::size_t PeakUsedBytes{0};
        std::size_t LimitBytes{0};
        std::size_t PeakCapacityBytes{0};
        std::uint64_t GrowthCount{0};
    };

    /**
     * @brief 字节池的块尺寸、容量上限和分段增长策略。
     * @details BlockCount 是容量上限；InitialBlockCount 是启动时预分配的基线；
     *          GrowthBlockCount 是容量耗尽后每次新增的块数，最后一段自动截断到上限。
     *          InitialBlockCount 大于上限时按上限截断，以保留小容量测试的即时容量语义。
     *          本值不拥有资源，不绑定 executor；只在冷构造时消费。
     */
    struct BytePoolOptions final
    {
        std::size_t BlockSize{64 * 1024};  ///< 单个连续字节租约的最大容量。
        std::size_t BlockCount{2048};      ///< 默认上限 128 MiB。
        std::size_t InitialBlockCount{64}; ///< 默认启动时预分配 4 MiB。
        std::size_t GrowthBlockCount{64};  ///< 默认按 4 MiB 分段扩容。
    };
} // namespace Prism::Memory
