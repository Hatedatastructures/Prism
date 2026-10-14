/**
 * @file ProtocolAssembly.hpp
 * @brief Preview 静态协议枚举及协议目录映射。
 */

#pragma once

#include <Preview/Composition/Protocol/ProtocolCatalog.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace Preview::Application::Assembly
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

    [[nodiscard]] inline auto ParseStaticProtocol(const std::string_view Name)
        -> std::optional<StaticProtocol>
    {
        const auto Descriptor = Preview::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor || Descriptor->Kind != Preview::Composition::Protocol::DescriptorKind::Protocol ||
            !Descriptor->SupportsTcp)
        {
            return std::nullopt;
        }
        switch (Descriptor->Id)
        {
        case Preview::Contract::ProtocolType::Http:
            return StaticProtocol::Http;
        case Preview::Contract::ProtocolType::Socks5:
            return StaticProtocol::Socks5;
        case Preview::Contract::ProtocolType::Vless:
            return StaticProtocol::Vless;
        case Preview::Contract::ProtocolType::Trojan:
            return StaticProtocol::Trojan;
        case Preview::Contract::ProtocolType::Vmess:
            return StaticProtocol::Vmess;
        case Preview::Contract::ProtocolType::Shadowsocks:
            return StaticProtocol::Shadowsocks2022;
        case Preview::Contract::ProtocolType::AnyTls:
            return StaticProtocol::AnyTls;
        case Preview::Contract::ProtocolType::TrustTunnel:
            return StaticProtocol::TrustTunnel;
        default:
            return std::nullopt;
        }
    }

    [[nodiscard]] inline auto IsQuicProtocolName(const std::string_view Name) noexcept -> bool
    {
        return Name == "hysteria2" || Name == "tuic";
    }

    [[nodiscard]] inline auto ParseHexDigit(const char Character) noexcept -> int
    {
        if (Character >= '0' && Character <= '9')
            return Character - '0';
        if (Character >= 'a' && Character <= 'f')
            return Character - 'a' + 10;
        if (Character >= 'A' && Character <= 'F')
            return Character - 'A' + 10;
        return -1;
    }

    [[nodiscard]] inline auto ParseUuid(const std::string_view Text)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        std::array<std::uint8_t, 16> Result{};
        std::size_t Output = 0;
        int High = -1;
        for (const char Character : Text)
        {
            if (Character == '-')
            {
                continue;
            }
            const auto Digit = ParseHexDigit(Character);
            if (Digit < 0 || Output >= Result.size())
            {
                return std::nullopt;
            }
            if (High < 0)
            {
                High = Digit;
            }
            else
            {
                Result[Output++] = static_cast<std::uint8_t>((High << 4) | Digit);
                High = -1;
            }
        }
        if (Output != Result.size() || High >= 0)
        {
            return std::nullopt;
        }
        return Result;
    }

} // namespace Preview::Application::Assembly
