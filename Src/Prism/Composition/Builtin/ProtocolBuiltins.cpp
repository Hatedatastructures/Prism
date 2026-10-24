/** @file ProtocolBuiltins.cpp @brief 固定顺序的 builtin 注册实现。 */

#include <Prism/Composition/Builtin/ProtocolBuiltins.hpp>

namespace Prism::Composition::Builtin
{

    auto ProtocolBuiltinCapabilities() noexcept -> CapabilitySet
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

    auto MakeStaticBuiltinRegistry() -> Registry
    {
        return Registry(RegistryOptions{ProtocolBuiltinCapabilities()});
    }

    namespace
    {

        auto IsDisabled(const StaticBuiltinSpec& Spec,
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

        auto MakeDescriptor(const StaticBuiltinSpec& Spec) -> BuiltinDescriptor
        {
            BuiltinDescriptor Descriptor;
            Descriptor.Kind = Prism::KindId::From(Spec.Kind);
            Descriptor.Name = Prism::NameId::From(Spec.Name);
            Descriptor.Provides = Spec.Provides;
            Descriptor.Requires = Spec.Requires;
            // 静态目录本身不拥有运行时对象；调用 descriptor 必须明确失败，
            // 由 Composition 在启动编排阶段提供真正的 protocol/carrier callback。
            Descriptor.Callback = [](const BuiltinRequest&) -> Prism::Foundation::Expected<void>
            {
                return std::unexpected(Prism::Foundation::Error::NotFound);
            };
            return Descriptor;
        }

        auto RegisterKind(Registry& RegistryValue, const StaticBuiltinOptions& Options,
            const std::string_view Kind) -> Prism::Foundation::Expected<StaticBuiltinReport>
        {
            StaticBuiltinReport Report;
            for (const auto& Spec : Detail::Builtins)
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

    } // namespace

    auto RegisterStaticBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options) -> Prism::Foundation::Expected<StaticBuiltinReport>
    {
        return RegisterKind(RegistryValue, Options, {});
    }

    auto RegisterProtocolBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options) -> Prism::Foundation::Expected<StaticBuiltinReport>
    {
        return RegisterKind(RegistryValue, Options, "protocol");
    }

    auto RegisterCarrierBuiltins(Registry& RegistryValue,
        const StaticBuiltinOptions& Options) -> Prism::Foundation::Expected<StaticBuiltinReport>
    {
        return RegisterKind(RegistryValue, Options, "carrier");
    }

} // namespace Prism::Composition::Builtin
