/**
 * @file scheme.hpp
 * @brief WebSocket 伪装方案
 */

#pragma once

#include <prism/handshake/ws/config.hpp>
#include <prism/handshake/scheme.hpp>

namespace psm::handshake::ws
{

    /**
     * @class scheme
     * @brief WebSocket 传输伪装方案
     * @details TLS + HTTP/1.1 升级（WebSocket）。SNI 路由命中后：
     *          TLS 握手 → 解析 HTTP GET 请求（Upgrade: websocket）→
     *          响应 101 → 建立 WS 帧传输 → executor 二次探测内层协议。
     */
    class scheme final : public psm::handshake::scheme
    {
    public:
        [[nodiscard]] auto name() const noexcept -> std::string_view override;

        [[nodiscard]] auto active(const psm::settings &cfg) const noexcept -> bool override;

        [[nodiscard]] auto snis(const psm::settings &cfg) const
            -> memory::vector<memory::string> override;

        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 2;
        }

        [[nodiscard]] auto guess(const psm::settings &cfg) const
            -> verify_result override;

        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;
    };

} // namespace psm::handshake::ws
