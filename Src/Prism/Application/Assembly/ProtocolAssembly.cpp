/** @file ProtocolAssembly.cpp @brief Prism 静态协议映射与 UUID 解析实现。 */
#include <Prism/Application/Assembly/ProtocolAssembly.hpp>

#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

namespace Prism::Application::Assembly
{

    auto ParseStaticProtocol(const std::string_view Name)
        -> std::optional<StaticProtocol>
    {
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor || Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol ||
            !Descriptor->SupportsTcp)
        {
            return std::nullopt;
        }
        switch (Descriptor->Id)
        {
        case Prism::Contract::ProtocolType::Http:
            return StaticProtocol::Http;
        case Prism::Contract::ProtocolType::Socks5:
            return StaticProtocol::Socks5;
        case Prism::Contract::ProtocolType::Vless:
            return StaticProtocol::Vless;
        case Prism::Contract::ProtocolType::Trojan:
            return StaticProtocol::Trojan;
        case Prism::Contract::ProtocolType::Vmess:
            return StaticProtocol::Vmess;
        case Prism::Contract::ProtocolType::Shadowsocks:
            return StaticProtocol::Shadowsocks2022;
        case Prism::Contract::ProtocolType::AnyTls:
            return StaticProtocol::AnyTls;
        case Prism::Contract::ProtocolType::TrustTunnel:
            return StaticProtocol::TrustTunnel;
        default:
            return std::nullopt;
        }
    }

    auto IsQuicProtocolName(const std::string_view Name) noexcept -> bool
    {
        return Name == "hysteria2" || Name == "tuic";
    }

    auto ParseHexDigit(const char Character) noexcept -> int
    {
        if (Character >= '0' && Character <= '9')
            return Character - '0';
        if (Character >= 'a' && Character <= 'f')
            return Character - 'a' + 10;
        if (Character >= 'A' && Character <= 'F')
            return Character - 'A' + 10;
        return -1;
    }

    auto ParseUuid(const std::string_view Text)
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

} // namespace Prism::Application::Assembly
