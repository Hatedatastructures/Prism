/**
 * @file ProcessMemory.hpp
 * @brief 在显式冷快照时读取当前进程 RSS / working set。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace Prism::Memory
{
    /**
     * @brief 由操作系统读取的当前与峰值驻留内存值。
     * @details Windows 字段取进程 working set；Linux 字段取 RSS。均包含共享驻留页，非 Prism 私有分配统计。
     */
    struct ProcessMemoryUsage final
    {
        std::uint64_t CurrentResidentBytes{0};
        std::uint64_t PeakResidentBytes{0};
    };

    /**
     * @brief 在调用方指定的冷快照边界读取当前进程驻留内存。
     * @details Windows 动态查询 psapi；Linux 读取 /proc/self/statm 与 getrusage。
     *          不适用于 packet/data 热路径；不支持的平台或 OS 查询失败返回空值。
     * @return 独立值快照；失败返回 std::nullopt。
     */
    [[nodiscard]] auto ReadProcessMemoryUsage() noexcept -> std::optional<ProcessMemoryUsage>;
}
