/**
 * @file Generation.hpp
 * @brief Prism generation、账户、入口和日志配置的启动阶段。
 */

#pragma once

#include <Prism/Account/Account.hpp>
#include <Prism/Application/Application.hpp>
#include <Prism/Application/Assembly/Account.hpp>
#include <Prism/Application/Assembly/Capability.hpp>
#include <Prism/Application/Assembly/Dns.hpp>
#include <Prism/Application/Startup/Detail/BoundaryServices.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Application/Startup/Detail/Configuration.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Application::Startup::GenerationPhase
{

    namespace Net = boost::asio;
    namespace Configuration = Prism::Application::Configuration;
    namespace Builtin = Prism::Composition::Builtin;
    namespace Assembly = Prism::Application::Assembly;

    struct Request final
    {
        std::filesystem::path ConfigurationPath;
        std::function<std::optional<std::string>(std::string_view)> SecretResolver;
    };

    struct Result final
    {
        Configuration::SharedConfigurationGeneration Generation;
        AccountCatalog Accounts;
        Net::ip::tcp::endpoint Endpoint;
        std::optional<Net::ip::udp::endpoint> UdpEndpoint;
        std::optional<Net::ip::tcp::endpoint> OperationsEndpoint;
        std::optional<Prism::Diagnose::LogLevel> ConfiguredLogLevel;
        std::optional<Prism::Diagnose::RenderMode> ConfiguredRenderMode;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
    };

    /** @brief 完整解析和校验配置后发布不可变 generation，不拥有运行时入口。 */
    [[nodiscard]] inline auto BuildGeneration(Request RequestValue)
        -> std::expected<Configuration::SharedConfigurationGeneration, StartupError>
    {
        const auto Capabilities = Assembly::ApplicationCapabilities();
        Configuration::ValidationOptions Validation;
        Validation.Secrets = Configuration::SecretRefResolver(std::move(RequestValue.SecretResolver));
        Validation.AvailableCapabilities = Capabilities;
        auto Prepared = Configuration::ConfigurationParser::PrepareFile(
            Configuration::LoadRequest{RequestValue.ConfigurationPath, std::move(Validation)});
        if (!Prepared)
        {
            auto ErrorCode = StartupErrorCode::InvalidConfiguration;
            if (Prepared.error().Code == Configuration::ConfigurationErrorCode::FileOpen)
            {
                ErrorCode = StartupErrorCode::MissingConfiguration;
            }
            return std::unexpected(
                Startup::MakeStartupError(ErrorCode, Prepared.error().Path, Prepared.error().Message));
        }

        const auto Required = Assembly::RequiredCapabilities(Prepared->Configuration());
        if (!Required)
        {
            return std::unexpected(Required.error());
        }

        auto Registry = Builtin::MakeStaticBuiltinRegistry();
        const auto Registered = Builtin::RegisterStaticBuiltins(Registry,{});
        if (!Registered)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Builtin, {},
                "Prism builtin registration failed"));
        }
        const auto Snapshot =
            Registry.Freeze(Builtin::FreezeRequest{*Required, "Prism", Prism::GenerationId{1}});
        if (!Snapshot)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Builtin, {},
                "Prism builtin snapshot freeze failed"));
        }

        if (const auto Supported =
                ConfigurationStartup::ValidateSupportedServices(Prepared->Configuration(), *Snapshot);
            !Supported)
        {
            return std::unexpected(Supported.error());
        }

        const auto Generation = Configuration::GenerationBuilder::Build(
            Configuration::PreparedGenerationBuildRequest{std::move(*Prepared), *Snapshot, Capabilities,
                Prism::GenerationId{1}});
        if (!Generation)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Generation,
                Generation.error().Path, Generation.error().Message));
        }

        return *Generation;
    }
    /** @brief 按协议冻结账户服务 owner；失败返回 typed 启动错误。 */
    [[nodiscard]] inline auto BuildAccounts(Result& Phase) -> std::expected<void, StartupError>
    {
        auto Identities = std::make_shared<AccountIdentityRegistry>();
        auto IdentityPreparation = Identities->BeginPreparation();
        if (!IdentityPreparation)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Accounts", "账户身份准备owner不可用"));
        }
        auto Store = std::make_shared<Prism::Account::AccountStore>(Prism::Account::StoreOptions{
            .WorkerCount = static_cast<std::uint32_t>(Phase.Generation->Configuration().Runtime.WorkerCount),
            .RuntimeRegistry = Identities->RuntimeRegistry(),
            .RevokeRuntimesOnSeal = false});
        auto Prepared = Assembly::PrepareAccountCatalog(
            {Phase.Generation, Store, *IdentityPreparation});
        if (!Prepared) return std::unexpected(Prepared.error());
        const auto RuntimePrepared = Store->PrepareRuntimeTransaction(Prepared->Update);
        if (!RuntimePrepared)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
                "Accounts", "账户 runtime 事务无法准备"));
        }
        const auto Published = Store->CommitSnapshot(Prepared->Update);
        if (!Published) return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
            "Accounts", "账户快照发布被拒绝"));
        Prepared->Catalog.RuntimeTransaction = *RuntimePrepared;
        Phase.Accounts = std::move(Prepared->Catalog);
        return {};
    }

    /** @brief 校验监听地址、日志和控制入口；仅探测 TCP bind，不启动协程。 */
    [[nodiscard]] inline auto BuildEntrypoints(Result& Phase) -> std::expected<void, StartupError>
    {
        const auto Endpoint =
            BoundaryStartup::MakeEndpoint(Phase.Generation->Configuration().Listeners.Tcp.front());
        if (!Endpoint)
        {
            return std::unexpected(Endpoint.error());
        }
        if (const auto Credentials =
                ConfigurationStartup::ValidateSampleCredentials(Phase.Generation->Configuration(), *Endpoint);
            !Credentials)
        {
            return std::unexpected(Credentials.error());
        }
        if (const auto Available = BoundaryStartup::CheckBindAvailable(*Endpoint); !Available)
        {
            return std::unexpected(Available.error());
        }

        std::optional<Net::ip::udp::endpoint> UdpEndpoint;
        if (!Phase.Generation->Configuration().Listeners.Udp.empty())
        {
            const auto ParsedUdp =
                BoundaryStartup::MakeUdpEndpoint(Phase.Generation->Configuration().Listeners.Udp.front());
            if (!ParsedUdp)
            {
                return std::unexpected(ParsedUdp.error());
            }
            UdpEndpoint = *ParsedUdp;
        }
        else if (!Phase.Generation->Configuration().Listeners.Quic.empty())
        {
            const auto ParsedQuic =
                BoundaryStartup::MakeUdpEndpoint(Phase.Generation->Configuration().Listeners.Quic.front());
            if (!ParsedQuic)
            {
                return std::unexpected(ParsedQuic.error());
            }
            UdpEndpoint = *ParsedQuic;
        }

        std::optional<Net::ip::tcp::endpoint> OperationsEndpoint;
        if (Phase.Generation->Configuration().Operations.Enabled)
        {
            const auto ParsedOperations = BoundaryStartup::MakeOperationsEndpoint(
                Phase.Generation->Configuration().Operations.Endpoint);
            if (!ParsedOperations)
            {
                return std::unexpected(ParsedOperations.error());
            }
            OperationsEndpoint = *ParsedOperations;
        }

        const auto ConfiguredLogLevel =
            ConfigurationStartup::ParseDiagnoseLogLevel(Phase.Generation->Configuration().Logging.Level);
        if (!ConfiguredLogLevel)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Logging.Level", "unsupported Prism logging level"));
        }
        const auto ConfiguredRenderMode = ConfigurationStartup::ParseDiagnoseRenderMode(
            Phase.Generation->Configuration().Logging.RenderMode);
        if (!ConfiguredRenderMode)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Logging.RenderMode", "unsupported Prism logging render mode"));
        }

        Phase.Endpoint = *Endpoint;
        Phase.UdpEndpoint = std::move(UdpEndpoint);
        Phase.OperationsEndpoint = std::move(OperationsEndpoint);
        Phase.ConfiguredLogLevel = *ConfiguredLogLevel;
        Phase.ConfiguredRenderMode = *ConfiguredRenderMode;
        Phase.UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        return {};
    }
    [[nodiscard]] inline auto Build(Request RequestValue) -> std::expected<Result, StartupError>
    {
        const auto Generation = BuildGeneration(std::move(RequestValue));
        if (!Generation)
            return std::unexpected(Generation.error());
        Result Phase;
        Phase.Generation = *Generation;
        if (const auto Accounts = BuildAccounts(Phase); !Accounts)
            return std::unexpected(Accounts.error());
        if (const auto Entrypoints = BuildEntrypoints(Phase); !Entrypoints)
            return std::unexpected(Entrypoints.error());
        return Phase;
    }
} // namespace Prism::Application::Startup::GenerationPhase
