/**
 * @file types.hpp
 * @brief XHTTP 伪装方案类型定义
 * @details XHTTP = TLS + HTTP/2 + stream-one（单 POST 长连接）。
 *          客户端经 h2 POST {path} 建立双向流，服务端响应 200 后
 *          流量透明传输（HTTP/2 DATA 帧承载）。
 */

#pragma once

#include <common/core/memory/container.hpp>

namespace preview::xhttp
{

    /**
     * @struct config
     * @brief XHTTP 方案配置
     */
    struct config
    {
        memory::string path{"/"}; ///< POST 路径前缀

        /**
         * @brief 方案是否启用
         * @return 始终可用（由调用方决定挂载）
         */
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !path.empty();
        }
    };

} // namespace preview::xhttp
