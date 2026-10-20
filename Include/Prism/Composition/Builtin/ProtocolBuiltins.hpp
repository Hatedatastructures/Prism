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
#include <string_view>
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
    [[nodiscard]] auto ProtocolBuiltinCapabilities() noexcept -> CapabilitySet;

    /** @brief 创建已经装配静态协议能力的启动注册表。 */
    [[nodiscard]] auto MakeStaticBuiltinRegistry() -> Registry;

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
    [[nodiscard]] auto RegisterStaticBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options) -> Prism::Foundation::Expected<StaticBuiltinReport>;

    /** @brief 只注册协议 builtin。 */
    [[nodiscard]] auto RegisterProtocolBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options = {}) -> Prism::Foundation::Expected<StaticBuiltinReport>;

    /** @brief 只注册 carrier builtin。 */
    [[nodiscard]] auto RegisterCarrierBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options = {}) -> Prism::Foundation::Expected<StaticBuiltinReport>;

} // namespace Prism::Composition::Builtin
