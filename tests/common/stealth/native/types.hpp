/**
 * @file types.hpp
 * @brief Native 伪装方案类型定义
 * @details Native 是原生 TLS 兜底方案：服务端完成 TLS 握手后
 *          直通（传输透明，无内层协议伪装）。配置为空结构，
 *          仅作为方案占位与聚合头入口。
 */

#pragma once

#include <common/core/memory/container.hpp>

namespace psmtest::native
{

    /**
     * @struct config
     * @brief Native 方案配置
     * @details 当前无配置项（TLS 证书由调用方 SSL 上下文提供）。
     */
    struct config
    {
        /// 方案是否启用（native 始终可用，由调用方决定是否挂载）
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return true;
        }
    };

} // namespace psmtest::native
