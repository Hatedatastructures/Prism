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
        UdpAssociation,
        QuicBinding,
        DnsResolve,
        RouteLookup,
        Dial,
    };

    struct TcpRecognitionBinding
    {
        std::string_view Name;
        Preview::Recognition::ProtocolType Protocol;
    };

    struct UdpAssociationBinding
    {
        std::string_view Name;
        Preview::Recognition::ProtocolType Protocol;
    };

    struct QuicAlpnBinding
    {
        std::string_view Alpn;
        Preview::Recognition::ProtocolType Protocol;
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

        [[nodiscard]] static auto UdpAssociations() noexcept
            -> std::span<const UdpAssociationBinding>
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
            Preview::Recognition::ProtocolType Protocol) noexcept
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
            Preview::Recognition::ProtocolType Protocol) noexcept -> OperationScope
        {
            if (Protocol == Preview::Recognition::ProtocolType::Hysteria2 ||
                Protocol == Preview::Recognition::ProtocolType::Tuic)
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
            TcpRecognitionBinding{"http", Preview::Recognition::ProtocolType::Http},
            TcpRecognitionBinding{"socks5", Preview::Recognition::ProtocolType::Socks5},
            TcpRecognitionBinding{"vless", Preview::Recognition::ProtocolType::Vless},
            TcpRecognitionBinding{"trojan", Preview::Recognition::ProtocolType::Trojan},
            TcpRecognitionBinding{"vmess", Preview::Recognition::ProtocolType::Vmess},
            TcpRecognitionBinding{"ss2022", Preview::Recognition::ProtocolType::Shadowsocks},
            TcpRecognitionBinding{"anytls", Preview::Recognition::ProtocolType::AnyTls},
            TcpRecognitionBinding{"trusttunnel", Preview::Recognition::ProtocolType::TrustTunnel},
        };

        inline static constexpr std::array<UdpAssociationBinding, 7> UdpBindings_{
            UdpAssociationBinding{"socks5", Preview::Recognition::ProtocolType::Socks5},
            UdpAssociationBinding{"vless", Preview::Recognition::ProtocolType::Vless},
            UdpAssociationBinding{"trojan", Preview::Recognition::ProtocolType::Trojan},
            UdpAssociationBinding{"vmess", Preview::Recognition::ProtocolType::Vmess},
            UdpAssociationBinding{"ss2022", Preview::Recognition::ProtocolType::Shadowsocks},
            UdpAssociationBinding{"hysteria2", Preview::Recognition::ProtocolType::Hysteria2},
            UdpAssociationBinding{"tuic", Preview::Recognition::ProtocolType::Tuic},
        };

        inline static constexpr std::array<QuicAlpnBinding, 2> QuicBindings_{
            QuicAlpnBinding{"h3", Preview::Recognition::ProtocolType::Hysteria2},
            QuicAlpnBinding{"h3", Preview::Recognition::ProtocolType::Tuic},
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
