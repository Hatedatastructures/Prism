/**
 * @file Configuration.hpp
 * @brief Prism 配置校验和启动期配置值解析。
 */

#pragma once

#include <Prism/Application/Application.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Application/Startup/Detail/Diagnose.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace Prism::Application::ConfigurationStartup
{

    namespace Net = boost::asio;
    namespace Configuration = Prism::Application::Configuration;
    namespace Builtin = Prism::Composition::Builtin;
    namespace Core = Prism::Recognition;
    namespace Protocol = Prism::Composition::Protocol;

    [[nodiscard]] inline auto ParseDiagnoseLogLevel(const std::string_view Value) noexcept
        -> std::optional<Prism::Diagnose::LogLevel>
    {
        using Prism::Diagnose::LogLevel;
        if (Value == "Trace")
            return LogLevel::Trace;
        if (Value == "Debug")
            return LogLevel::Debug;
        if (Value == "Info")
            return LogLevel::Info;
        if (Value == "Access")
            return LogLevel::Access;
        if (Value == "Warn")
            return LogLevel::Warn;
        if (Value == "Error")
            return LogLevel::Error;
        if (Value == "Critical")
            return LogLevel::Critical;
        if (Value == "Off")
            return LogLevel::Off;
        return std::nullopt;
    }

    [[nodiscard]] inline auto ParseDiagnoseRenderMode(const std::string_view Value) noexcept
        -> std::optional<Prism::Diagnose::RenderMode>
    {
        using Prism::Diagnose::RenderMode;
        if (Value == "CompactHuman")
            return RenderMode::CompactHuman;
        if (Value == "HumanWithFields")
            return RenderMode::HumanWithFields;
        if (Value == "Structured")
            return RenderMode::Structured;
        return std::nullopt;
    }

    [[nodiscard]] inline auto FindStaticBuiltin(
        const std::shared_ptr<const Builtin::BuiltinSnapshot>& Snapshot,
        const Configuration::BuiltinConfiguration& Configured) -> const Builtin::RegisteredBuiltin*
    {
        if (!Snapshot)
        {
            return nullptr;
        }
        for (const auto& Entry : Snapshot->Entries())
        {
            if (Entry.Descriptor.Kind.Value() == Configured.Kind &&
                Entry.Descriptor.Name.Value() == Configured.Name)
            {
                return &Entry;
            }
        }
        return nullptr;
    }

    /** @brief 冷验证导出的协议资源需求；仅本次启动校验拥有，不保存运行期状态。 */
    struct SupportedProtocols final
    {
        struct TlsRequirement final
        {
            std::size_t Index;
            Protocol::ProtocolDescriptor Descriptor;
        };
        std::vector<TlsRequirement> TlsRequirements;
        bool HasTcpProtocol{false};
        bool HasQuicProtocol{false};
    };

    /** @brief 借用冷配置校验共享 socket 布局；同步返回首个 typed 错误，不启动或关闭资源。 */
    [[nodiscard]] inline auto ValidateListenerLayout(const Configuration::PrismConfiguration& ConfigurationValue)
        -> std::expected<void, StartupError>
    {
       if (ConfigurationValue.Listeners.Tcp.size() != 1U)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Listeners.Tcp", "Prism requires exactly one configured TCP listener"));
        }
        if (ConfigurationValue.Listeners.Udp.size() > 1U || ConfigurationValue.Listeners.Quic.size() > 1U)
        {
            return std::unexpected(
                Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration, "Listeners",
                    "Prism uses one shared UDP socket; configure at most one Udp and one Quic endpoint"));
        }
        if (!ConfigurationValue.Listeners.Udp.empty() && !ConfigurationValue.Listeners.Quic.empty())
        {
            const auto& Udp = ConfigurationValue.Listeners.Udp.front();
            const auto& Quic = ConfigurationValue.Listeners.Quic.front();
            if (Udp.Address != Quic.Address || Udp.Port != Quic.Port)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                    "Listeners.Quic[0]", "Udp and Quic must share the same address and numeric port"));
            }
        }
        return {};
    }

    /** @brief 借用协议声明导出唯一资源需求；同步按配置顺序保留错误优先级，无异步取消或半关闭。 */
    [[nodiscard]] inline auto InspectSupportedProtocols(const Configuration::PrismConfiguration& ConfigurationValue)
        -> std::expected<SupportedProtocols, StartupError>
    {
        if (ConfigurationValue.Protocols.empty())
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Protocols", "Prism requires at least one configured TCP protocol"));
        }
        if (ConfigurationValue.Protocols.size() >= Core::CandidateBitmap::Capacity)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Protocols", "Prism supports at most 127 TCP protocol candidates"));
        }
        std::unordered_set<Prism::Contract::ProtocolType> SeenProtocols;
        SupportedProtocols Needs;

        for (std::size_t Index = 0; Index < ConfigurationValue.Protocols.size(); ++Index)
        {
            const auto& Protocol = ConfigurationValue.Protocols[Index];
            const auto Descriptor = Protocol::ProtocolCatalog::Find(Protocol.Builtin);
            const auto Path = "Protocols[" + std::to_string(Index) + "]";
            if (!Descriptor || Descriptor->Kind != Protocol::DescriptorKind::Protocol ||
                Protocol.Name != Protocol.Builtin)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    Path, "configured protocol has no matching typed descriptor"));
            }
            if (!SeenProtocols.emplace(Descriptor->Id).second)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration, Path,
                    "duplicate protocol candidate"));
            }
            if (Descriptor->SupportsQuic)
            {
                if (!Protocol.Quic)
                {
                    return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                        Path, "configured QUIC protocol requires its typed QUIC configuration"));
                }
                Needs.HasQuicProtocol = true;
            }
            else if (Protocol.Quic)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    Path + ".Quic", "configured protocol does not provide a QUIC binding"));
            }
            else if (Descriptor->SupportsTcp)
            {
                Needs.HasTcpProtocol = true;
            }
            else
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    Path, "configured protocol has no supported TCP or QUIC entry"));
            }
            if (Descriptor->TlsResource != Protocol::TlsResourceRequirement::None)
            {
                Needs.TlsRequirements.push_back({Index, *Descriptor});
            }
        }
        return Needs;
    }

    /** @brief 在 caller 的冷路径 executor 校验协议所需 listener/TLS；输入只借用到返回。 */
    [[nodiscard]] inline auto ValidateProtocolPrerequisites(const Configuration::PrismConfiguration& ConfigurationValue,
        const SupportedProtocols& Needs) -> std::expected<void, StartupError>
    {
        if (!Needs.HasTcpProtocol)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                "Protocols", "Prism requires at least one TCP protocol alongside QUIC protocols"));
        }
        if (Needs.HasQuicProtocol && ConfigurationValue.Listeners.Quic.empty())
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Listeners.Quic", "a configured Hysteria2 or TUIC protocol requires a QUIC listener"));
        }
        const auto NativeCertificate = ConfigurationValue.NativeTls.Enabled &&
            !ConfigurationValue.NativeTls.CertificateFile.empty() &&
            !ConfigurationValue.NativeTls.PrivateKeyFile.empty();
        for (const auto& Requirement : Needs.TlsRequirements)
        {
            if (Requirement.Descriptor.TlsResource == Protocol::TlsResourceRequirement::NativeCertificate &&
                !NativeCertificate)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    "Protocols", std::string(Requirement.Descriptor.Name) +
                        " requires an enabled NativeTls certificate and private key"));
            }
        }
        return {};
    }

    /** @brief 校验已有 carrier 并返回 native 证书资源是否完整；不持有配置或运行期 owner。 */
    [[nodiscard]] inline auto InspectSupportedCarriers(const Configuration::PrismConfiguration& ConfigurationValue)
        -> std::expected<bool, StartupError>
    {
        bool HasNativeCarrier = false;
        for (std::size_t Index = 0; Index < ConfigurationValue.Carriers.size(); ++Index)
        {
            const auto& Carrier = ConfigurationValue.Carriers[Index];
            const auto Descriptor = Protocol::ProtocolCatalog::Find(Carrier.Builtin);
            if (!Descriptor || Descriptor->Kind != Protocol::DescriptorKind::Carrier)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    "Carriers[" + std::to_string(Index) + "]",
                    "configured carrier has no Prism admission callback: " + Carrier.Builtin));
            }
            if (const auto* Options = std::get_if<Prism::Contract::NativeTlsOptions>(&Carrier.Options);
                Options != nullptr && !Options->CertificateFile.empty() && !Options->PrivateKeyFile.empty())
            {
                HasNativeCarrier = true;
            }
        }
        return HasNativeCarrier;
    }

    /** @brief 复杂冷资源边界借用配置/协议需求/native 可用值，返回首个外层 TLS 不满足错误。 */
    [[nodiscard]] inline auto ValidateOuterTls(const Configuration::PrismConfiguration& ConfigurationValue,
        const SupportedProtocols& Needs, bool HasNativeCarrier) -> std::expected<void, StartupError>
    {
        const auto NativeCertificate = ConfigurationValue.NativeTls.Enabled &&
            !ConfigurationValue.NativeTls.CertificateFile.empty() &&
            !ConfigurationValue.NativeTls.PrivateKeyFile.empty();
        for (const auto& Requirement : Needs.TlsRequirements)
        {
            if (NativeCertificate)
            {
                continue;
            }
            if (Requirement.Descriptor.TlsResource ==
                    Protocol::TlsResourceRequirement::NativeCertificateOrCarrier && HasNativeCarrier)
            {
                continue;
            }
            const auto IsQuic = Requirement.Descriptor.SupportsQuic;
            auto Path = std::string("Protocols[") + std::to_string(Requirement.Index) + "]";
            auto Message = std::string(Requirement.Descriptor.Name) +
                " requires an enabled NativeTls certificate and private key";
            if (IsQuic)
            {
                Path = "Listeners.Quic";
                Message = "QUIC protocols require an enabled NativeTls certificate and private key or a native certificate carrier";
            }
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                Path, Message));
        }
        return {};
    }

    /** @brief 同步校验剩余路由和冻结 builtin 的可调用性；不构造业务 plane 或持有 callback。 */
    [[nodiscard]] inline auto ValidateConfiguredBindings(const Configuration::PrismConfiguration& ConfigurationValue,
        const std::shared_ptr<const Builtin::BuiltinSnapshot>& Snapshot) -> std::expected<void, StartupError>
    {
        if (!ConfigurationValue.Routes.empty())
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService, "Routes",
                "configured routes are not wired into Prism startup"));
        }
        for (const auto& Configured : ConfigurationValue.Builtins)
        {
            const auto* Entry = FindStaticBuiltin(Snapshot, Configured);
            if (Entry == nullptr)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    "Builtins." + Configured.Id,
                    "configured builtin has no registered Prism implementation"));
            }
            if (!Snapshot->Invoke(Builtin::InvocationRequest{Entry->Id}))
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    "Builtins." + Configured.Id,
                    "configured builtin descriptor has no callable Prism callback"));
            }
        }
        return {};
    }

    /** @brief caller 冷路径按原错误顺序验证所有启用资源；输入借用到返回，输出 typed 错误或成功。 */
    [[nodiscard]] inline auto ValidateSupportedServices(const Configuration::PrismConfiguration& ConfigurationValue,
        const std::shared_ptr<const Builtin::BuiltinSnapshot>& Snapshot) -> std::expected<void, StartupError>
    {
        if (const auto Layout = ValidateListenerLayout(ConfigurationValue); !Layout) return Layout;
        const auto Protocols = InspectSupportedProtocols(ConfigurationValue);
        if (!Protocols) return std::unexpected(Protocols.error());
        if (const auto Required = ValidateProtocolPrerequisites(ConfigurationValue, *Protocols); !Required) return Required;
        const auto Carriers = InspectSupportedCarriers(ConfigurationValue);
        if (!Carriers) return std::unexpected(Carriers.error());
        if (const auto Tls = ValidateOuterTls(ConfigurationValue, *Protocols, *Carriers); !Tls) return Tls;
        return ValidateConfiguredBindings(ConfigurationValue, Snapshot);
    }

    [[nodiscard]] inline auto IsSampleCredential(const std::string_view Credential) noexcept -> bool
    {
        return Credential == "local-token" || Credential == "password" || Credential == "change-me" ||
            Credential == "changeme";
    }

    [[nodiscard]] inline auto ValidateSampleCredentials(
        const Configuration::PrismConfiguration& ConfigurationValue, const Net::ip::tcp::endpoint& Endpoint)
        -> std::expected<void, StartupError>
    {
        if (Endpoint.address().is_loopback())
        {
            return {};
        }
        for (const auto& Account : ConfigurationValue.Accounts)
        {
            if (Account.SecretRef.empty() && IsSampleCredential(Account.Credential))
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                    "Accounts." + Account.Id + ".Credential",
                    "sample credentials are only allowed on a loopback TCP listener"));
            }
        }
        return {};
    }

} // namespace Prism::Application::ConfigurationStartup
