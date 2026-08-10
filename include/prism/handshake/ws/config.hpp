/**
 * @file config.hpp
 * @brief WebSocket 伪装方案配置
 */

#pragma once

#include <prism/foundation/memory/container.hpp>

#include <cstdint>

namespace psm::handshake::ws
{

    /**
     * @struct config
     * @brief WebSocket 传输伪装配置
     * @details SNI 白名单决定该方案在识别流水线中的命中条件。
     */
    struct config
    {
        memory::vector<memory::string> server_names; ///< SNI 白名单
        memory::string path{"/"};                    ///< WebSocket 升级路径

        /// 是否启用
        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !server_names.empty();
        }
    };

} // namespace psm::handshake::ws
