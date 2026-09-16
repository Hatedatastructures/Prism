/**
 * @file ProtocolCatalog.hpp
 * @brief Preview 内建协议/carrier 的静态能力目录。
 * @details 目录只保存不可变 wire/入口能力，不执行 I/O，也不拥有
 *          Application、Session 或账号对象。应用启动阶段从目录编译
 *          generation，运行时只消费 descriptor 值。
 */
#pragma once

#include <Preview/Composition/Builtin/Capability.hpp>
#include <Preview/Composition/Recognition/ProtocolMatrix.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace Preview::Composition::Protocol
{

    enum class DescriptorKind : std::uint8_t
    {
        Protocol,
        Carrier,
    };

    struct ProtocolDescriptor final
    {
        DescriptorKind Kind{DescriptorKind::Protocol};
        Preview::Recognition::ProtocolType Id{Preview::Recognition::ProtocolType::Unknown};
        std::string_view Name;
        Preview::Composition::Recognition::OperationScope Scope{
            Preview::Composition::Recognition::OperationScope::TcpRecognition};
        Builtin::CapabilitySet Requires{};
        Builtin::CapabilitySet Provides{};
        bool SupportsTcp{false};
        bool SupportsUdp{false};
        bool SupportsQuic{false};
    };

    class ProtocolCatalog final
    {
    public:
        [[nodiscard]] static auto All() noexcept -> std::span<const ProtocolDescriptor>
        {
            return Descriptors_;
        }

        [[nodiscard]] static auto Find(const std::string_view Name) noexcept
            -> std::optional<ProtocolDescriptor>
        {
            const auto CanonicalName = Name == "shadowsocks2022" ? std::string_view{"ss2022"}
                                                                   : Name;
            const auto It = std::find_if(
                Descriptors_.begin(), Descriptors_.end(),
                [CanonicalName](const ProtocolDescriptor &Descriptor)
                { return Descriptor.Name == CanonicalName; });
            if (It == Descriptors_.end())
            {
                return std::nullopt;
            }
            return *It;
        }

        [[nodiscard]] static auto Find(const Preview::Recognition::ProtocolType Id) noexcept
            -> std::optional<ProtocolDescriptor>
        {
            const auto It = std::find_if(
                Descriptors_.begin(), Descriptors_.end(),
                [Id](const ProtocolDescriptor &Descriptor) { return Descriptor.Id == Id; });
            if (It == Descriptors_.end())
            {
                return std::nullopt;
            }
            return *It;
        }

        [[nodiscard]] static auto Supports(
            const std::string_view Name,
            const Preview::Composition::Recognition::OperationScope Scope) noexcept -> bool
        {
            const auto Descriptor = Find(Name);
            if (!Descriptor)
            {
                return false;
            }
            switch (Scope)
            {
            case Preview::Composition::Recognition::OperationScope::TcpRecognition:
                return Descriptor->SupportsTcp;
            case Preview::Composition::Recognition::OperationScope::UdpAssociation:
                return Descriptor->SupportsUdp;
            case Preview::Composition::Recognition::OperationScope::QuicBinding:
                return Descriptor->SupportsQuic;
            default:
                return true;
            }
        }

    private:
        inline static constexpr std::array<ProtocolDescriptor, 17> Descriptors_{
            ProtocolDescriptor{DescriptorKind::Protocol, Preview::Recognition::ProtocolType::Http,
                               "http", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false,
                               false},
            ProtocolDescriptor{DescriptorKind::Protocol, Preview::Recognition::ProtocolType::Socks5,
                               "socks5", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport},
                               Builtin::CapabilitySet{Builtin::Capability::Stream,
                                                       Builtin::Capability::Datagram},
                               true, true, false},
            ProtocolDescriptor{DescriptorKind::Protocol, Preview::Recognition::ProtocolType::Vless,
                               "vless", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport},
                               Builtin::CapabilitySet{Builtin::Capability::Stream,
                                                       Builtin::Capability::Datagram},
                               true, true, false},
            ProtocolDescriptor{DescriptorKind::Protocol, Preview::Recognition::ProtocolType::Trojan,
                               "trojan", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport},
                               Builtin::CapabilitySet{Builtin::Capability::Stream,
                                                       Builtin::Capability::Datagram},
                               true, true, false},
            ProtocolDescriptor{DescriptorKind::Protocol, Preview::Recognition::ProtocolType::Vmess,
                               "vmess", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport},
                               Builtin::CapabilitySet{Builtin::Capability::Stream,
                                                       Builtin::Capability::Datagram},
                               true, true, false},
            ProtocolDescriptor{DescriptorKind::Protocol,
                               Preview::Recognition::ProtocolType::Shadowsocks,
                               "ss2022", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport},
                               Builtin::CapabilitySet{Builtin::Capability::Stream,
                                                       Builtin::Capability::Datagram},
                               true, true, false},
            ProtocolDescriptor{DescriptorKind::Protocol,
                               Preview::Recognition::ProtocolType::Hysteria2,
                               "hysteria2", Recognition::OperationScope::QuicBinding,
                               Builtin::CapabilitySet{Builtin::Capability::Quic},
                               Builtin::CapabilitySet{Builtin::Capability::Quic,
                                                       Builtin::Capability::Alpn},
                               false, false, true},
            ProtocolDescriptor{DescriptorKind::Protocol, Preview::Recognition::ProtocolType::Tuic,
                               "tuic", Recognition::OperationScope::QuicBinding,
                               Builtin::CapabilitySet{Builtin::Capability::Quic},
                               Builtin::CapabilitySet{Builtin::Capability::Quic,
                                                       Builtin::Capability::Alpn},
                               false, false, true},
            ProtocolDescriptor{DescriptorKind::Protocol,
                               Preview::Recognition::ProtocolType::AnyTls,
                               "anytls", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport,
                                                       Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream,
                                                       Builtin::Capability::Multiplex},
                               true, false, false},
            ProtocolDescriptor{DescriptorKind::Protocol,
                               Preview::Recognition::ProtocolType::TrustTunnel,
                               "trusttunnel", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Transport,
                                                       Builtin::Capability::Tls,
                                                       Builtin::Capability::Alpn},
                               Builtin::CapabilitySet{Builtin::Capability::Stream,
                                                       Builtin::Capability::Datagram},
                               true, true, false},
            ProtocolDescriptor{DescriptorKind::Carrier, Preview::Recognition::ProtocolType::Tls,
                               "native", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false,
                               false},
            ProtocolDescriptor{DescriptorKind::Carrier, Preview::Recognition::ProtocolType::Tls,
                               "reality", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false,
                               false},
            ProtocolDescriptor{DescriptorKind::Carrier, Preview::Recognition::ProtocolType::Tls,
                               "shadowtls", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false,
                               false},
            ProtocolDescriptor{DescriptorKind::Carrier, Preview::Recognition::ProtocolType::Tls,
                               "restls", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false,
                               false},
            ProtocolDescriptor{DescriptorKind::Carrier, Preview::Recognition::ProtocolType::Tls,
                               "ws", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false,
                               false},
            ProtocolDescriptor{DescriptorKind::Carrier, Preview::Recognition::ProtocolType::Tls,
                               "xhttp", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, true,
                               false},
            ProtocolDescriptor{DescriptorKind::Carrier, Preview::Recognition::ProtocolType::Tls,
                               "gun", Recognition::OperationScope::TcpRecognition,
                               Builtin::CapabilitySet{Builtin::Capability::Tls},
                               Builtin::CapabilitySet{Builtin::Capability::Stream}, true, false,
                               false}};
    };

} // namespace Preview::Composition::Protocol
