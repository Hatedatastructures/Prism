/**
 * @file ProtocolMatrix.hpp
 * @brief TCP 识别、UDP 关联和 QUIC ALPN 绑定的纯元数据矩阵。
 * @details 该文件不包含任何具体协议实现；协议 adapter 通过名字和类型
 *          显式接入，避免 TCP 识别路径、UDP 关联路径和 QUIC stream 路径
 *          互相猜测或形成协议间 include。
 */

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <Prism/Runtime/Recognition/Protocol.hpp>

namespace Prism::Composition::Recognition
{

    enum class OperationScope : std::uint8_t
    {
        TcpRecognition,
        DatagramAssociation,
        QuicBinding,
        DnsResolve,
        RouteLookup,
        Dial,
    };

    struct TcpRecognitionBinding
    {
        std::string_view Name;
        Prism::Contract::ProtocolType Protocol;
    };

    struct DatagramAssociationBinding
    {
        std::string_view Name;
        Prism::Contract::ProtocolType Protocol;
    };

    struct QuicAlpnBinding
    {
        std::string_view Alpn;
        Prism::Contract::ProtocolType Protocol;
    };

    struct CarrierBinding
    {
        std::string_view Name;
        std::string_view Scheme;
    };

    class ProtocolMatrix final
    {
    public:
        [[nodiscard]] static auto TcpRecognition() noexcept
            -> std::span<const TcpRecognitionBinding>
        {
            return TcpBindings_;
        }

        [[nodiscard]] static auto DatagramAssociations() noexcept
            -> std::span<const DatagramAssociationBinding>
        {
            return UdpBindings_;
        }

        [[nodiscard]] static auto QuicAlpnBindings() noexcept
            -> std::span<const QuicAlpnBinding>
        {
            return QuicBindings_;
        }

        [[nodiscard]] static auto Carriers() noexcept -> std::span<const CarrierBinding>
        {
            return CarrierBindings_;
        }

        [[nodiscard]] static auto SupportsUdp(std::string_view Name) noexcept -> bool;

        [[nodiscard]] static auto FindQuic(
            std::string_view Alpn,
            Prism::Contract::ProtocolType Protocol) noexcept
            -> std::optional<QuicAlpnBinding>;

        [[nodiscard]] static auto ScopeFor(
            Prism::Contract::ProtocolType Protocol) noexcept -> OperationScope;

    private:
        [[nodiscard]] static auto EqualAscii(std::string_view Left,
                                              std::string_view Right) noexcept -> bool;

        inline static constexpr std::array<TcpRecognitionBinding, 8> TcpBindings_{
            TcpRecognitionBinding{"http", Prism::Contract::ProtocolType::Http},
            TcpRecognitionBinding{"socks5", Prism::Contract::ProtocolType::Socks5},
            TcpRecognitionBinding{"vless", Prism::Contract::ProtocolType::Vless},
            TcpRecognitionBinding{"trojan", Prism::Contract::ProtocolType::Trojan},
            TcpRecognitionBinding{"vmess", Prism::Contract::ProtocolType::Vmess},
            TcpRecognitionBinding{"ss2022", Prism::Contract::ProtocolType::Shadowsocks},
            TcpRecognitionBinding{"anytls", Prism::Contract::ProtocolType::AnyTls},
            TcpRecognitionBinding{"trusttunnel", Prism::Contract::ProtocolType::TrustTunnel},
        };

        inline static constexpr std::array<DatagramAssociationBinding, 7> UdpBindings_{
            DatagramAssociationBinding{"socks5", Prism::Contract::ProtocolType::Socks5},
            DatagramAssociationBinding{"vless", Prism::Contract::ProtocolType::Vless},
            DatagramAssociationBinding{"trojan", Prism::Contract::ProtocolType::Trojan},
            DatagramAssociationBinding{"vmess", Prism::Contract::ProtocolType::Vmess},
            DatagramAssociationBinding{"ss2022", Prism::Contract::ProtocolType::Shadowsocks},
            DatagramAssociationBinding{"hysteria2", Prism::Contract::ProtocolType::Hysteria2},
            DatagramAssociationBinding{"tuic", Prism::Contract::ProtocolType::Tuic},
        };

        inline static constexpr std::array<QuicAlpnBinding, 2> QuicBindings_{
            QuicAlpnBinding{"h3", Prism::Contract::ProtocolType::Hysteria2},
            QuicAlpnBinding{"h3", Prism::Contract::ProtocolType::Tuic},
        };

        inline static constexpr std::array<CarrierBinding, 9> CarrierBindings_{
            CarrierBinding{"native", "native"},
            CarrierBinding{"reality", "reality"},
            CarrierBinding{"shadowtls", "shadowtls"},
            CarrierBinding{"restls", "restls"},
            CarrierBinding{"anytls", "anytls"},
            CarrierBinding{"trusttunnel", "trusttunnel"},
            CarrierBinding{"ws", "ws"},
            CarrierBinding{"xhttp", "xhttp"},
            CarrierBinding{"gun", "gun"},
        };
    };

} // namespace Prism::Composition::Recognition
