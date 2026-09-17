/**
 * @file Types.hpp
 * @brief XHTTP 伪装方案类型定义
 * @details XHTTP = TLS + HTTP/2 + Stream-one（单 POST 长连接）。
 *          客户端经 h2 POST {Path} 建立双向流，服务端响应 200 后
 *          流量透明传输（HTTP/2 DATA 帧承载）。
 */

#pragma once

#include <string>

namespace Preview::Xhttp
{

    /**
     * @struct Config
     * @brief XHTTP 方案配置
     * @note Path 为空时方案不可用；是否挂载由调用方决定。
     */
    struct Config
    {
        std::string Path{"/"}; ///< POST 路径前缀
        std::string Host{}; ///< 可选的 :authority 约束
        std::string Mode{"StreamOne"}; ///< StreamOne / StreamUp / PacketUp

        /**
         * @brief 方案是否启用
         * @return 始终可用（由调用方决定挂载）
         */
        [[nodiscard]] auto Enabled() const noexcept -> bool
        {
            return !Path.empty() &&
                   (Mode == "StreamOne" || Mode == "StreamUp" || Mode == "PacketUp");
        }

        [[nodiscard]] auto IsSplit() const noexcept -> bool
        {
            return Mode == "StreamUp" || Mode == "PacketUp";
        }
    };

} // namespace Preview::Xhttp
