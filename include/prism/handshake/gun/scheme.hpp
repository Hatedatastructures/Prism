/**
 * @file scheme.hpp
 * @brief gRPC (gun) 伪装方案
 */

#pragma once

#include <prism/handshake/gun/config.hpp>
#include <prism/handshake/scheme.hpp>

namespace psm::handshake::gun
{

    /**
     * @class scheme
     * @brief gRPC (gun) 传输伪装方案
     * @details TLS + HTTP/2 + gRPC 帧伪装。SNI 路由命中后：
     *          TLS 握手（ALPN h2）→ HTTP/2 会话 → 匹配 POST /GunService/Tun
     *          → 提取双向流（gun 帧编解码）→ 交由 executor 二次探测内层协议。
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

} // namespace psm::handshake::gun
