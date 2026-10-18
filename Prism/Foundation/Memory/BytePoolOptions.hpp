/**
 * @file BytePoolOptions.hpp
 * @brief worker 冷路径字节池的固定容量配置。
 */
#pragma once

#include <cstddef>

namespace Prism::Memory
{
    /**
     * @brief 字节池创建后不再增长的块尺寸与数量。
     * @details 两项都必须非零，乘积和块标记数组大小必须可表示。
     *          本值不拥有资源，不绑定 executor；只在冷构造时消费。
     */
    struct BytePoolOptions final
    {
        std::size_t BlockSize{64 * 1024}; ///< 单个连续字节租约的最大容量。
        std::size_t BlockCount{2048}; ///< 默认共 128 MiB，排队、使用中及跨异步租约共享。
    };
}
