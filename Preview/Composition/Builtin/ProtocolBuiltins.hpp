/**
 * @file ProtocolBuiltins.hpp
 * @brief Preview 协议与 carrier 的静态 builtin 描述。
 * @details 描述表只保存稳定元数据；协议 I/O、认证和数据面由
 *          Composition adapter 或 Front 通过显式回调接入，不在注册阶段执行。
 */

#pragma once

#include <array>
#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Composition/Builtin/Registry.hpp>

namespace Preview::Composition::Builtin
{

    /** @brief builtin 注册键。 */
    struct BuiltinKey
    {
        std::string_view Kind;
        std::string_view Name;

        friend constexpr auto operator==(const BuiltinKey &, const BuiltinKey &) noexcept -> bool = default;
    };

    /** @brief 静态 builtin 注册选项。 */
    struct StaticBuiltinOptions
    {
        std::vector<BuiltinKey> Disabled;
    };

    /** @brief 静态 builtin 注册统计。 */
    struct StaticBuiltinReport
    {
        std::size_t Registered{0};
        std::size_t Disabled{0};
    };

    /** @brief 不包含回调的编译期描述项。 */
    struct StaticBuiltinSpec
    {
        std::string_view Kind;
        std::string_view Name;
        CapabilitySet Provides;
        CapabilitySet Requires;
    };

    namespace StaticBuiltinName
    {
        inline constexpr std::string_view Http{"http"};
        inline constexpr std::string_view Socks5{"socks5"};
        inline constexpr std::string_view Vless{"vless"};
        inline constexpr std::string_view Trojan{"trojan"};
        inline constexpr std::string_view Vmess{"vmess"};
        inline constexpr std::string_view Shadowsocks2022{"ss2022"};
        inline constexpr std::string_view Hysteria2{"hysteria2"};
        inline constexpr std::string_view Tuic{"tuic"};
        inline constexpr std::string_view NativeTls{"native"};
        inline constexpr std::string_view Reality{"reality"};
        inline constexpr std::string_view ShadowTls{"shadowtls"};
        inline constexpr std::string_view Restls{"restls"};
        inline constexpr std::string_view AnyTls{"anytls"};
        inline constexpr std::string_view TrustTunnel{"trusttunnel"};
        inline constexpr std::string_view Websocket{"ws"};
        inline constexpr std::string_view Xhttp{"xhttp"};
        inline constexpr std::string_view Gun{"gun"};
    } // namespace StaticBuiltinName

    /**
     * @brief 所有协议/carrier 所需的启动能力闭包。
     * @return 可直接传给 Registry 的初始能力集合。
     */
    [[nodiscard]] inline auto ProtocolBuiltinCapabilities() noexcept -> CapabilitySet
    {
        return CapabilitySet{
            Capability::Core,
            Capability::Request,
            Capability::Memory,
            Capability::Executor,
            Capability::Cancellation,
            Capability::Transport,
            Capability::Stream,
            Capability::Datagram,
            Capability::Tls,
            Capability::Multiplex,
            Capability::Inbound,
            Capability::Outbound,
            Capability::Session,
            Capability::Quic,
            Capability::Alpn,
            Capability::Dns,
            Capability::Route,
            Capability::Dial,
            Capability::Front,
            Capability::Operation,
        };
    }

    /** @brief 创建已经装配静态协议能力的启动注册表。 */
    [[nodiscard]] inline auto MakeStaticBuiltinRegistry() -> Registry
    {
        return Registry(RegistryOptions{ProtocolBuiltinCapabilities()});
    }

    namespace Detail
    {

        inline constexpr auto ProtocolRequires =
            CapabilitySet{Capability::Core, Capability::Request, Capability::Transport};
        inline constexpr auto StreamDatagramProvides =
            CapabilitySet{Capability::Stream, Capability::Datagram};
        inline constexpr auto QuicProvides =
            CapabilitySet{Capability::Quic, Capability::Alpn};
        inline constexpr auto CarrierRequires =
            CapabilitySet{Capability::Core, Capability::Transport, Capability::Tls};
        inline constexpr auto CarrierProvides =
            CapabilitySet{Capability::Tls, Capability::Stream};

        inline constexpr std::array<StaticBuiltinSpec, 17> Builtins{
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Http,
                              CapabilitySet{Capability::Stream}, ProtocolRequires},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Socks5,
                              StreamDatagramProvides, ProtocolRequires},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Vless,
                              StreamDatagramProvides, ProtocolRequires},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Trojan,
                              StreamDatagramProvides, ProtocolRequires},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Vmess,
                              StreamDatagramProvides, ProtocolRequires},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Shadowsocks2022,
                              StreamDatagramProvides, ProtocolRequires},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Hysteria2,
                              QuicProvides, ProtocolRequires | CapabilitySet{Capability::Quic}},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::Tuic,
                              QuicProvides, ProtocolRequires | CapabilitySet{Capability::Quic}},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::AnyTls,
                              CapabilitySet{Capability::Stream, Capability::Multiplex},
                              ProtocolRequires | CapabilitySet{Capability::Tls}},
            StaticBuiltinSpec{"protocol", StaticBuiltinName::TrustTunnel,
                              StreamDatagramProvides,
                              ProtocolRequires | CapabilitySet{Capability::Tls, Capability::Alpn}},
            StaticBuiltinSpec{"carrier", StaticBuiltinName::NativeTls,
                              CarrierProvides, CarrierRequires},
            StaticBuiltinSpec{"carrier", StaticBuiltinName::Reality,
                              CarrierProvides, CarrierRequires},
            StaticBuiltinSpec{"carrier", StaticBuiltinName::ShadowTls,
                              CarrierProvides, CarrierRequires},
            StaticBuiltinSpec{"carrier", StaticBuiltinName::Restls,
                              CarrierProvides, CarrierRequires},
            StaticBuiltinSpec{"carrier", StaticBuiltinName::Websocket,
                              CarrierProvides, CarrierRequires},
            StaticBuiltinSpec{"carrier", StaticBuiltinName::Xhttp,
                              CarrierProvides, CarrierRequires},
            StaticBuiltinSpec{"carrier", StaticBuiltinName::Gun,
                              CarrierProvides, CarrierRequires},
        };

        [[nodiscard]] inline auto IsDisabled(const StaticBuiltinSpec &Spec,
                                             const StaticBuiltinOptions &Options) noexcept -> bool
        {
            for (const auto &Key : Options.Disabled)
            {
                if (Key.Kind == Spec.Kind && Key.Name == Spec.Name)
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] inline auto MakeDescriptor(const StaticBuiltinSpec &Spec) -> BuiltinDescriptor
        {
            BuiltinDescriptor Descriptor;
            Descriptor.Kind = Preview::KindId::From(Spec.Kind);
            Descriptor.Name = Preview::NameId::From(Spec.Name);
            Descriptor.Provides = Spec.Provides;
            Descriptor.Requires = Spec.Requires;
            // 静态目录本身不拥有运行时对象；调用 descriptor 必须明确失败，
            // 由 Composition 在启动编排阶段提供真正的 protocol/carrier callback。
            Descriptor.Callback = [](const BuiltinRequest &) -> Preview::Foundation::Expected<void>
            {
                return std::unexpected(Preview::Foundation::Error::NotFound);
            };
            return Descriptor;
        }

        [[nodiscard]] inline auto RegisterKind(
            Registry &RegistryValue,
            const StaticBuiltinOptions &Options,
            std::string_view Kind) -> Preview::Foundation::Expected<StaticBuiltinReport>
        {
            StaticBuiltinReport Report;
            for (const auto &Spec : Builtins)
            {
                if (!Kind.empty() && Spec.Kind != Kind)
                {
                    continue;
                }
                if (IsDisabled(Spec, Options))
                {
                    ++Report.Disabled;
                    continue;
                }
                const auto Id = RegistryValue.Register(MakeDescriptor(Spec));
                if (!Id)
                {
                    return std::unexpected(Id.error());
                }
                ++Report.Registered;
            }
            return Report;
        }

    } // namespace Detail

    /** @brief 获取稳定静态描述表。 */
    [[nodiscard]] inline auto StaticBuiltinSpecs() noexcept -> std::span<const StaticBuiltinSpec>
    {
        return Detail::Builtins;
    }

    /**
     * @brief 按固定顺序注册所有协议和 carrier builtin。
     * @param RegistryValue 启动阶段可变注册表。
     * @param Options 禁用项；禁用只跳过注册，不改变其余顺序。
     */
    [[nodiscard]] inline auto RegisterStaticBuiltins(
        Registry &RegistryValue,
        const StaticBuiltinOptions &Options) -> Preview::Foundation::Expected<StaticBuiltinReport>
    {
        return Detail::RegisterKind(RegistryValue, Options, {});
    }

    /** @brief 只注册协议 builtin。 */
    [[nodiscard]] inline auto RegisterProtocolBuiltins(
        Registry &RegistryValue,
        const StaticBuiltinOptions &Options = {}) -> Preview::Foundation::Expected<StaticBuiltinReport>
    {
        return Detail::RegisterKind(RegistryValue, Options, "protocol");
    }

    /** @brief 只注册 carrier builtin。 */
    [[nodiscard]] inline auto RegisterCarrierBuiltins(
        Registry &RegistryValue,
        const StaticBuiltinOptions &Options = {}) -> Preview::Foundation::Expected<StaticBuiltinReport>
    {
        return Detail::RegisterKind(RegistryValue, Options, "carrier");
    }

    /** @brief 兼容更明确的调用名。 */
    [[nodiscard]] inline auto RegisterProtocolAndCarrierBuiltins(
        Registry &RegistryValue,
        const StaticBuiltinOptions &Options = {}) -> Preview::Foundation::Expected<StaticBuiltinReport>
    {
        return RegisterStaticBuiltins(RegistryValue, Options);
    }

    /** @brief 静态协议/carrier 注册的常用别名。 */
    [[nodiscard]] inline auto RegisterAllBuiltins(
        Registry &RegistryValue,
        const StaticBuiltinOptions &Options = {}) -> Preview::Foundation::Expected<StaticBuiltinReport>
    {
        return RegisterStaticBuiltins(RegistryValue, Options);
    }

    /** @brief 面向启动器的描述注册别名。 */
    [[nodiscard]] inline auto RegisterBuiltinDescriptors(
        Registry &RegistryValue,
        const StaticBuiltinOptions &Options = {}) -> Preview::Foundation::Expected<StaticBuiltinReport>
    {
        return RegisterStaticBuiltins(RegistryValue, Options);
    }

} // namespace Preview::Composition::Builtin
