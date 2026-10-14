/**
 * @file ProtocolMatrix.hpp
 * @brief TCP 识别、UDP 关联和 QUIC ALPN 绑定的纯元数据矩阵。
 * @details 该文件不包含任何具体协议实现；协议 adapter 通过名字和类型
 *          显式接入，避免 TCP 识别路径、UDP 关联路径和 QUIC stream 路径
 *          互相猜测或形成协议间 include。
 */

#pragma once

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <Preview/Runtime/Recognition/Protocol.hpp>

namespace Preview::Composition::Recognition
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
        Preview::Contract::ProtocolType Protocol;
    };

    struct DatagramAssociationBinding
    {
        std::string_view Name;
        Preview::Contract::ProtocolType Protocol;
    };

    struct QuicAlpnBinding
    {
        std::string_view Alpn;
        Preview::Contract::ProtocolType Protocol;
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

        [[nodiscard]] static auto SupportsUdp(std::string_view Name) noexcept -> bool
        {
            return std::any_of(UdpBindings_.begin(), UdpBindings_.end(),
                               [Name](const auto &Binding) { return EqualAscii(Binding.Name, Name); });
        }

        [[nodiscard]] static auto FindQuic(
            std::string_view Alpn,
            Preview::Contract::ProtocolType Protocol) noexcept
            -> std::optional<QuicAlpnBinding>
        {
            for (const auto &Binding : QuicBindings_)
            {
                if (Binding.Protocol == Protocol && EqualAscii(Binding.Alpn, Alpn))
                {
                    return Binding;
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ScopeFor(
            Preview::Contract::ProtocolType Protocol) noexcept -> OperationScope
        {
            if (Protocol == Preview::Contract::ProtocolType::Hysteria2 ||
                Protocol == Preview::Contract::ProtocolType::Tuic)
            {
                return OperationScope::QuicBinding;
            }
            return OperationScope::TcpRecognition;
        }

    private:
        [[nodiscard]] static auto EqualAscii(std::string_view Left,
                                              std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                auto Lower = [](const char Character) noexcept -> char
                {
                    if (Character >= 'A' && Character <= 'Z')
                    {
                        return static_cast<char>(Character + ('a' - 'A'));
                    }
                    return Character;
                };
                if (Lower(Left[Index]) != Lower(Right[Index]))
                {
                    return false;
                }
            }
            return true;
        }

        inline static constexpr std::array<TcpRecognitionBinding, 8> TcpBindings_{
            TcpRecognitionBinding{"http", Preview::Contract::ProtocolType::Http},
            TcpRecognitionBinding{"socks5", Preview::Contract::ProtocolType::Socks5},
            TcpRecognitionBinding{"vless", Preview::Contract::ProtocolType::Vless},
            TcpRecognitionBinding{"trojan", Preview::Contract::ProtocolType::Trojan},
            TcpRecognitionBinding{"vmess", Preview::Contract::ProtocolType::Vmess},
            TcpRecognitionBinding{"ss2022", Preview::Contract::ProtocolType::Shadowsocks},
            TcpRecognitionBinding{"anytls", Preview::Contract::ProtocolType::AnyTls},
            TcpRecognitionBinding{"trusttunnel", Preview::Contract::ProtocolType::TrustTunnel},
        };

        inline static constexpr std::array<DatagramAssociationBinding, 7> UdpBindings_{
            DatagramAssociationBinding{"socks5", Preview::Contract::ProtocolType::Socks5},
            DatagramAssociationBinding{"vless", Preview::Contract::ProtocolType::Vless},
            DatagramAssociationBinding{"trojan", Preview::Contract::ProtocolType::Trojan},
            DatagramAssociationBinding{"vmess", Preview::Contract::ProtocolType::Vmess},
            DatagramAssociationBinding{"ss2022", Preview::Contract::ProtocolType::Shadowsocks},
            DatagramAssociationBinding{"hysteria2", Preview::Contract::ProtocolType::Hysteria2},
            DatagramAssociationBinding{"tuic", Preview::Contract::ProtocolType::Tuic},
        };

        inline static constexpr std::array<QuicAlpnBinding, 2> QuicBindings_{
            QuicAlpnBinding{"h3", Preview::Contract::ProtocolType::Hysteria2},
            QuicAlpnBinding{"h3", Preview::Contract::ProtocolType::Tuic},
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

} // namespace Preview::Composition::Recognition
