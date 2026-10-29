/**
 * @file Protocol.hpp
 * @brief Prism 静态协议枚举及协议目录映射。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace Prism::Application::Assembly
{

    enum class StaticProtocol : std::uint8_t
    {
        Http,
        Socks5,
        Vless,
        Trojan,
        Vmess,
        Shadowsocks2022,
        AnyTls,
        TrustTunnel,
    };

    [[nodiscard]] auto ParseStaticProtocol(const std::string_view Name)
        -> std::optional<StaticProtocol>;

    [[nodiscard]] auto IsQuicProtocolName(const std::string_view Name) noexcept -> bool;

    [[nodiscard]] auto ParseHexDigit(const char Character) noexcept -> int;

    [[nodiscard]] auto ParseUuid(const std::string_view Text)
        -> std::optional<std::array<std::uint8_t, 16>>;

} // namespace Prism::Application::Assembly
