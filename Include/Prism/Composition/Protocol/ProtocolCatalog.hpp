/**
 * @file ProtocolCatalog.hpp
 * @brief Prism 内建协议/carrier 的静态能力目录。
 * @details 目录只保存不可变 wire/入口能力，不执行 I/O，也不拥有
 *          Application、Session 或账号对象。应用启动阶段从目录编译
 *          generation，运行时只消费 descriptor 值。
 */
#pragma once

#include <Prism/Composition/Builtin/Capability.hpp>
#include <Prism/Composition/Recognition/ProtocolMatrix.hpp>
#include <Prism/Contract/Ingress/Protocol.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

namespace Prism::Composition::Protocol
{
    /** @brief 五种互不混淆的正式装配槽位；配置别名只在本目录规范化一次。 */
    enum class ProviderCategory : std::uint8_t
    {
        TcpProxy,
        QuicProxy,
        TlsCarrier,
        Mux,
        Ech,
    };

    /**
     * @brief TLS recognition 类型。
     * @details Native 至 Gun 七种拥有 typed carrier descriptor；TrustTunnel 仅表示 TLS 后的协议候选，
     *          不构成 carrier provider slot，也不能通过 RegisterTlsCarrier 注册。
     */
    enum class CarrierKind : std::uint8_t
    {
        None,
        Native,
        Reality,
        Shadowtls,
        Restls,
        WebSocket,
        Xhttp,
        Gun,
        TrustTunnel,
    };

    enum class MuxSlot : std::uint8_t
    {
        Binding,
    };

    enum class EchSlot : std::uint8_t
    {
        ServerKeys,
    };

    using ProviderIdentity = std::variant<Prism::Contract::ProtocolType, CarrierKind, MuxSlot, EchSlot>;

    /** @brief 可直接索引槽位的 typed identity；热路径不从字符串反推。 */
    struct ProviderKey final
    {
        ProviderCategory Category;
        ProviderIdentity Identity;
        friend auto operator==(const ProviderKey&, const ProviderKey&) noexcept -> bool = default;
    };

    enum class DescriptorKind : std::uint8_t
    {
        Protocol,
        Carrier,
    };

    /** @brief 协议监听准备阶段所需的证书 owner。 */
    enum class TlsResourceRequirement : std::uint8_t
    {
        None,
        NativeCertificate,
        NativeCertificateOrCarrier,
    };

    struct ProtocolDescriptor final
    {
        DescriptorKind Kind{DescriptorKind::Protocol};
        Prism::Contract::ProtocolType Id{Prism::Contract::ProtocolType::Unknown};
        std::string_view Name;
        Prism::Composition::Recognition::OperationScope Scope{
            Prism::Composition::Recognition::OperationScope::TcpRecognition};
        Builtin::CapabilitySet Requires{};
        Builtin::CapabilitySet Provides{};
        bool SupportsTcp{false};
        bool SupportsUdp{false};
        bool SupportsQuic{false};
        CarrierKind Carrier{CarrierKind::None};
        std::string_view AccountKey;
        TlsResourceRequirement TlsResource{TlsResourceRequirement::None};

        /** @brief 按 descriptor 的类别生成无歧义正式槽位键。 */
        [[nodiscard]] constexpr auto Slot() const noexcept -> ProviderKey
        {
            if (Kind == DescriptorKind::Carrier)
            {
                return {ProviderCategory::TlsCarrier, Carrier};
            }
            if (SupportsQuic)
            {
                return {ProviderCategory::QuicProxy, Id};
            }
            return {ProviderCategory::TcpProxy, Id};
        }
    };

    class ProtocolCatalog final
    {
    public:
        [[nodiscard]] static constexpr auto All() noexcept -> std::span<const ProtocolDescriptor>
        {
            return Descriptors_;
        }

        [[nodiscard]] static auto Find(const std::string_view Name) noexcept
            -> std::optional<ProtocolDescriptor>;

        [[nodiscard]] static auto Find(const Prism::Contract::ProtocolType Id) noexcept
            -> std::optional<ProtocolDescriptor>;

        /** @brief 以协议、carrier、Mux 或 ECH 的 typed key 查询，不存在的槽位返回空。 */
        [[nodiscard]] static auto Find(const ProviderKey& Key) noexcept
            -> std::optional<ProtocolDescriptor>;

        [[nodiscard]] static auto Find(const CarrierKind Kind) noexcept
            -> std::optional<ProtocolDescriptor>;

        [[nodiscard]] static auto CarrierName(const CarrierKind Kind) noexcept -> std::string_view;

        [[nodiscard]] static auto Supports(const std::string_view Name,
            const Prism::Composition::Recognition::OperationScope Scope) noexcept -> bool;

    private:
        inline static constexpr std::array<ProtocolDescriptor, 17> Descriptors_{
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Http, "http",
                Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false, false,
                CarrierKind::None, "Http"},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Socks5, "socks5",
                Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport},
                Builtin::CapabilitySet{Builtin::Capability::Stream, Builtin::Capability::Datagram,
                    Builtin::Capability::Multiplex},
                true, true, false, CarrierKind::None, "Socks5"},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Vless, "vless",
                Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport},
                Builtin::CapabilitySet{Builtin::Capability::Stream, Builtin::Capability::Datagram,
                    Builtin::Capability::Multiplex},
                true, true, false, CarrierKind::None, "Vless"},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Trojan, "trojan",
                Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport},
                Builtin::CapabilitySet{Builtin::Capability::Stream, Builtin::Capability::Datagram,
                    Builtin::Capability::Multiplex},
                true, true, false, CarrierKind::None, "Trojan"},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Vmess, "vmess",
                Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport},
                Builtin::CapabilitySet{Builtin::Capability::Stream, Builtin::Capability::Datagram,
                    Builtin::Capability::Multiplex},
                true, true, false, CarrierKind::None, "Vmess"},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Shadowsocks,
                "ss2022", Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport},
                Builtin::CapabilitySet{Builtin::Capability::Stream, Builtin::Capability::Datagram,
                    Builtin::Capability::Multiplex},
                true, true, false, CarrierKind::None, "Shadowsocks2022"},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Hysteria2,
                "hysteria2", Recognition::OperationScope::QuicBinding,
                Builtin::CapabilitySet{Builtin::Capability::Quic},
                Builtin::CapabilitySet{Builtin::Capability::Quic, Builtin::Capability::Alpn}, false, false,
                true, CarrierKind::None, {}, TlsResourceRequirement::NativeCertificateOrCarrier},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::Tuic, "tuic",
                Recognition::OperationScope::QuicBinding, Builtin::CapabilitySet{Builtin::Capability::Quic},
                Builtin::CapabilitySet{Builtin::Capability::Quic, Builtin::Capability::Alpn}, false, false,
                true, CarrierKind::None, {}, TlsResourceRequirement::NativeCertificateOrCarrier},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::AnyTls, "anytls",
                Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport, Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream, Builtin::Capability::Multiplex}, true,
                false, false, CarrierKind::None, "AnyTls",
                TlsResourceRequirement::NativeCertificateOrCarrier},
            ProtocolDescriptor{DescriptorKind::Protocol, Prism::Contract::ProtocolType::TrustTunnel,
                "trusttunnel", Recognition::OperationScope::TcpRecognition,
                Builtin::CapabilitySet{Builtin::Capability::Transport, Builtin::Capability::Tls,
                    Builtin::Capability::Alpn},
                Builtin::CapabilitySet{Builtin::Capability::Stream, Builtin::Capability::Datagram}, true,
                true, false, CarrierKind::None, "TrustTunnel",
                TlsResourceRequirement::NativeCertificate},
            ProtocolDescriptor{DescriptorKind::Carrier, Prism::Contract::ProtocolType::Tls, "native",
                Recognition::OperationScope::TcpRecognition, Builtin::CapabilitySet{Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false, false, CarrierKind::Native},
            ProtocolDescriptor{DescriptorKind::Carrier, Prism::Contract::ProtocolType::Tls, "reality",
                Recognition::OperationScope::TcpRecognition, Builtin::CapabilitySet{Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false, false, CarrierKind::Reality},
            ProtocolDescriptor{DescriptorKind::Carrier, Prism::Contract::ProtocolType::Tls, "shadowtls",
                Recognition::OperationScope::TcpRecognition, Builtin::CapabilitySet{Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false, false, CarrierKind::Shadowtls},
            ProtocolDescriptor{DescriptorKind::Carrier, Prism::Contract::ProtocolType::Tls, "restls",
                Recognition::OperationScope::TcpRecognition, Builtin::CapabilitySet{Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false, false, CarrierKind::Restls},
            ProtocolDescriptor{DescriptorKind::Carrier, Prism::Contract::ProtocolType::Tls, "ws",
                Recognition::OperationScope::TcpRecognition, Builtin::CapabilitySet{Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false, false, CarrierKind::WebSocket},
            ProtocolDescriptor{DescriptorKind::Carrier, Prism::Contract::ProtocolType::Tls, "xhttp",
                Recognition::OperationScope::TcpRecognition, Builtin::CapabilitySet{Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, true, false, CarrierKind::Xhttp},
            ProtocolDescriptor{DescriptorKind::Carrier, Prism::Contract::ProtocolType::Tls, "gun",
                Recognition::OperationScope::TcpRecognition, Builtin::CapabilitySet{Builtin::Capability::Tls},
                Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false, false, CarrierKind::Gun}};
    };

} // namespace Prism::Composition::Protocol
