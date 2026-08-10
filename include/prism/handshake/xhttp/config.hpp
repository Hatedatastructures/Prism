/**
 * @file config.hpp
 * @brief XHTTP 伪装方案配置
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <cstdint>

namespace psm::handshake::xhttp
{

    /**
     * @struct config
     * @brief XHTTP 传输伪装配置
     * @details 支持 stream-one / stream-up / packet-up 三种模式。
     */
    struct config
    {
        memory::vector<memory::string> server_names; ///< SNI 白名单
        memory::string path{"/"};                    ///< 路径前缀
        bool stream_one{true};                       ///< 允许 stream-one 模式
        bool stream_up{true};                        ///< 允许 stream-up 模式
        bool packet_up{true};                        ///< 允许 packet-up 模式

        /// 是否启用
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !server_names.empty();
        }
    };

} // namespace psm::handshake::xhttp
