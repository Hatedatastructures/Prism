/**
 * @file scheme.hpp
 * @brief XHTTP 伪装方案
 */

#pragma once

#include <prism/handshake/xhttp/config.hpp>
#include <prism/handshake/scheme.hpp>

namespace psm::handshake::xhttp
{

    /**
     * @class scheme
     * @brief XHTTP 传输伪装方案
     * @details TLS + HTTP/2（stream-one 模式）。SNI 路由命中后：
     *          TLS 握手（ALPN h2）→ HTTP/2 会话 → 匹配 POST {path}
     *          → 提取双向裸流 → executor 二次探测内层协议。
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

} // namespace psm::handshake::xhttp
