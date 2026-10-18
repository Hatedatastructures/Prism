/**
 * @file ProtocolBuiltins.hpp
 * @brief Prism 协议与 carrier 的静态 builtin 描述。
 * @details 描述表只保存稳定元数据；协议 I/O、认证和数据面由
 *          Composition adapter 或 Front 通过显式回调接入，不在注册阶段执行。
 */

#pragma once

#include <Prism/Composition/Builtin/Registry.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

#include <array>
#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Composition::Builtin
{

    /** @brief builtin 注册键。 */
    struct BuiltinKey
    {
        std::string_view Kind;
        std::string_view Name;

        friend constexpr auto operator==(const BuiltinKey&, const BuiltinKey&) noexcept -> bool = default;
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

        /** @brief 编译期由唯一 ProtocolCatalog 派生，名称/能力不再维护第二表。 */
        [[nodiscard]] constexpr auto DeriveBuiltins()
            -> std::array<StaticBuiltinSpec, Prism::Composition::Protocol::ProtocolCatalog::All().size()>
        {
            std::array<StaticBuiltinSpec, Prism::Composition::Protocol::ProtocolCatalog::All().size()>
                Result{};
            std::size_t Index = 0;
            for (const auto& Descriptor : Prism::Composition::Protocol::ProtocolCatalog::All())
            {
                const auto IsProtocol =
                    Descriptor.Kind == Prism::Composition::Protocol::DescriptorKind::Protocol;
                const auto BootstrapRequires = IsProtocol
                    ? CapabilitySet{Capability::Core, Capability::Request, Capability::Transport}
                    : CapabilitySet{Capability::Core, Capability::Transport, Capability::Tls};
                Result[Index++] = {Descriptor.Kind == Prism::Composition::Protocol::DescriptorKind::Protocol
                        ? "protocol"
                        : "carrier",
                    Descriptor.Name,
                    Descriptor.Provides | (IsProtocol ? CapabilitySet{} : CapabilitySet{Capability::Tls}),
                    Descriptor.Requires | BootstrapRequires};
            }
            return Result;
        }
        inline constexpr auto Builtins = DeriveBuiltins();

        [[nodiscard]] inline auto IsDisabled(const StaticBuiltinSpec& Spec,
            const StaticBuiltinOptions& Options) noexcept -> bool
        {
            for (const auto& Key : Options.Disabled)
            {
                if (Key.Kind == Spec.Kind && Key.Name == Spec.Name)
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] inline auto MakeDescriptor(const StaticBuiltinSpec& Spec) -> BuiltinDescriptor
        {
            BuiltinDescriptor Descriptor;
            Descriptor.Kind = Prism::KindId::From(Spec.Kind);
            Descriptor.Name = Prism::NameId::From(Spec.Name);
            Descriptor.Provides = Spec.Provides;
            Descriptor.Requires = Spec.Requires;
            // 静态目录本身不拥有运行时对象；调用 descriptor 必须明确失败，
            // 由 Composition 在启动编排阶段提供真正的 protocol/carrier callback。
            Descriptor.Callback = [](const BuiltinRequest&) -> Prism::Foundation::Expected<void>
            { return std::unexpected(Prism::Foundation::Error::NotFound); };
            return Descriptor;
        }

        [[nodiscard]] inline auto RegisterKind(Registry& RegistryValue, const StaticBuiltinOptions& Options,
            std::string_view Kind) -> Prism::Foundation::Expected<StaticBuiltinReport>
        {
            StaticBuiltinReport Report;
            for (const auto& Spec : Builtins)
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
    [[nodiscard]] inline auto RegisterStaticBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options) -> Prism::Foundation::Expected<StaticBuiltinReport>
    {
        return Detail::RegisterKind(RegistryValue, Options, {});
    }

    /** @brief 只注册协议 builtin。 */
    [[nodiscard]] inline auto RegisterProtocolBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options = {}) -> Prism::Foundation::Expected<StaticBuiltinReport>
    {
        return Detail::RegisterKind(RegistryValue, Options, "protocol");
    }

    /** @brief 只注册 carrier builtin。 */
    [[nodiscard]] inline auto RegisterCarrierBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options = {}) -> Prism::Foundation::Expected<StaticBuiltinReport>
    {
        return Detail::RegisterKind(RegistryValue, Options, "carrier");
    }

} // namespace Prism::Composition::Builtin
