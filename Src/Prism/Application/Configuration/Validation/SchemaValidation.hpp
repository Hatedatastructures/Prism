/**
 * @file SchemaValidation.hpp
 * @brief 配置 schema、监听器和 protocol-independent public settings 校验。
 */
#pragma once

#include <Prism/Application/Configuration/PublicSettingsValidator.hpp>
#include <Prism/Application/Configuration/Validation/CommonValidation.hpp>
#include <Prism/Application/Configuration/Validation/SecretValidation.hpp>

#include <cstdint>
#include <string>
#include <unordered_set>
#include <variant>
#include <vector>

namespace Prism::Application::Configuration::Validation
{

    inline constexpr std::uint32_t MaxWorkerCount = 4096U;
    /** @brief 进程级活动会话上限的配置上界；0 表示不限制。 */
    inline constexpr std::uint32_t MaxConnectionsLimit = 1024U * 1024U;

    [[nodiscard]] inline auto ValidateSchema(const PrismConfiguration &Configuration) -> Result
    {
        if (Configuration.SchemaVersion != 1U)
        {
            return Failure(ConfigurationErrorCode::UnsupportedSchemaVersion,
                           "SchemaVersion",
                           "only schema version 1 is supported");
        }
        if (Configuration.Runtime.WorkerCount == 0U ||
            Configuration.Runtime.WorkerCount > MaxWorkerCount)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Runtime.WorkerCount",
                           "WorkerCount must be between 1 and 4096");
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateTimeout(
                Configuration.Runtime.SessionTimeout, "Runtime.SessionTimeout");
            !ResultValue)
        {
            return ResultValue;
        }
        if (Configuration.Runtime.MaxConnections > MaxConnectionsLimit)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Runtime.MaxConnections",
                           "MaxConnections must not exceed 1048576");
        }

        const auto &Recognition = Configuration.Recognition;
        const bool ConfiguredMode = Recognition.Mode == "Configured";
        const bool MixedTrialMode = Recognition.Mode == "MixedTrial";
        const bool DeterministicMode = Recognition.Mode == "Deterministic";
        if (!ConfiguredMode && !MixedTrialMode && !DeterministicMode)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Recognition.Mode",
                           "mode must be Configured, MixedTrial, or Deterministic");
        }
        if (Recognition.ConfiguredCandidate < -1 || Recognition.ConfiguredCandidate > 127)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Recognition.ConfiguredCandidate",
                           "ConfiguredCandidate must be between -1 and 127");
        }
        if (!ConfiguredMode && Recognition.ConfiguredCandidate != -1)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Recognition.ConfiguredCandidate",
                           "ConfiguredCandidate is only valid in Configured mode");
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateEndpoints(
        const std::vector<ListenerEndpoint> &Endpoints,
        const std::string &Path,
        std::unordered_set<std::string> &Ids) -> Result
    {
        for (std::size_t Index = 0; Index < Endpoints.size(); ++Index)
        {
            const auto &Endpoint = Endpoints[Index];
            const auto ItemPath = Path + "[" + std::to_string(Index) + "]";
            if (const auto ResultValue = AddId(Ids, Endpoint.Id, ItemPath + ".Id"); !ResultValue)
            {
                return ResultValue;
            }
            if (Endpoint.Address.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               ItemPath + ".Address",
                               "listener Address is required");
            }
            if (Endpoint.Port == 0U)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               ItemPath + ".Port",
                               "port must be between 1 and 65535");
            }
            if (const auto ResultValue = PublicSettingsValidator::ValidateTimeout(
                    Endpoint.Timeout, ItemPath + ".Timeout");
                !ResultValue)
            {
                return ResultValue;
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateListeners(
        const PrismConfiguration &Configuration,
        std::unordered_set<std::string> &Ids) -> Result
    {
        if (Configuration.Listeners.Tcp.size() != 1U)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Listeners.Tcp",
                           "Prism requires exactly one configured TCP listener");
        }
        if (Configuration.Listeners.Udp.size() > 1U ||
            Configuration.Listeners.Quic.size() > 1U)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Listeners",
                           "configure at most one Udp and one Quic listener");
        }
        if (const auto ResultValue = ValidateEndpoints(
                Configuration.Listeners.Tcp, "Listeners.Tcp", Ids);
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateEndpoints(
                Configuration.Listeners.Udp, "Listeners.Udp", Ids);
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateEndpoints(
                Configuration.Listeners.Quic, "Listeners.Quic", Ids);
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateTimeout(
                Configuration.Listeners.Timeout, "Listeners.Timeout");
            !ResultValue)
        {
            return ResultValue;
        }
        if (!Configuration.Listeners.Udp.empty() && !Configuration.Listeners.Quic.empty())
        {
            const auto &Udp = Configuration.Listeners.Udp.front();
            const auto &Quic = Configuration.Listeners.Quic.front();
            if (Udp.Address != Quic.Address || Udp.Port != Quic.Port)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Listeners.Quic[0]",
                               "Udp and Quic must share the same address and numeric port");
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateNativeTls(
        const PrismConfiguration &Configuration) -> Result
    {
        if (Configuration.NativeTls.Enabled &&
            (Configuration.NativeTls.CertificateFile.empty() ||
             Configuration.NativeTls.PrivateKeyFile.empty()))
        {
            return Failure(ConfigurationErrorCode::MissingField,
                           "NativeTls",
                           "Enabled NativeTls requires CertificateFile and PrivateKeyFile");
        }
        const auto &Ech = Configuration.NativeTls.Ech;
        if (Ech.Enabled && (Ech.PrivateKeyFile.empty() || Ech.EchConfigFile.empty()))
        {
            return Failure(ConfigurationErrorCode::MissingField,
                           "NativeTls.Ech",
                           "Enabled ECH requires PrivateKeyFile and EchConfigFile");
        }
        if (!Ech.Enabled && (!Ech.PrivateKeyFile.empty() || !Ech.EchConfigFile.empty()))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "NativeTls.Ech",
                           "ECH key paths require Enabled");
        }
        if (Ech.Enabled && !Configuration.NativeTls.Enabled)
        {
            bool HasNativeTlsContext = false;
            for (const auto &Carrier : Configuration.Carriers)
            {
                const auto *Options = std::get_if<Prism::Contract::NativeTlsOptions>(
                    &Carrier.Options);
                if (Carrier.Builtin == "native" && Options &&
                    !Options->CertificateFile.empty() && !Options->PrivateKeyFile.empty())
                {
                    HasNativeTlsContext = true;
                    break;
                }
            }
            if (!HasNativeTlsContext)
            {
                return Failure(ConfigurationErrorCode::MissingField,
                               "NativeTls.Ech",
                               "ECH server keys require an enabled Native TLS context");
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateAccountGroups(
        const PrismConfiguration &Configuration) -> Result
    {
        std::unordered_set<std::string> GroupIds;
        std::unordered_set<std::string> GroupNames;
        for (std::size_t Index = 0; Index < Configuration.AccountGroups.size(); ++Index)
        {
            const auto &Group = Configuration.AccountGroups[Index];
            const auto Path = "AccountGroups[" + std::to_string(Index) + "]";
            if (!Prism::Account::ValidatePolicyConfiguration(Group.Policy))
                return Failure(ConfigurationErrorCode::InvalidValue, Path + ".Policy",
                               "用户组资源策略无效");
            if (Group.Id.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + ".Id",
                               "group Id is required");
            }
            if (!GroupIds.insert(Group.Id).second)
            {
                return Failure(ConfigurationErrorCode::DuplicateId,
                               Path + ".Id",
                               "group Id must be unique");
            }
            if (Group.Name.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + ".Name",
                               "group Name is required");
            }
            if (!GroupNames.insert(Group.Name).second)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + ".Name",
                               "group Name must be unique");
            }
        }

        for (std::size_t Index = 0; Index < Configuration.Accounts.size(); ++Index)
        {
            const auto &Account = Configuration.Accounts[Index];
            if (!Account.GroupId)
            {
                continue;
            }
            const auto Path = "Accounts[" + std::to_string(Index) + "].GroupId";
            if (Account.GroupId->empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "GroupId must be nonempty when present");
            }
            if (!GroupIds.contains(*Account.GroupId))
            {
                return Failure(ConfigurationErrorCode::MissingReference,
                               Path,
                               "GroupId does not reference a configured AccountGroup");
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateAccounts(
        const PrismConfiguration &Configuration,
        const ValidationOptions &Options,
        std::unordered_set<std::string> &Ids) -> Result
    {
        if (const auto ResultValue = ValidateAccountGroups(Configuration); !ResultValue)
        {
            return ResultValue;
        }
        for (std::size_t Index = 0; Index < Configuration.Accounts.size(); ++Index)
        {
            const auto &Account = Configuration.Accounts[Index];
            const auto Path = "Accounts[" + std::to_string(Index) + "]";
            if (!Prism::Account::ValidatePolicyConfiguration(Account.Policy))
                return Failure(ConfigurationErrorCode::InvalidValue, Path + ".Policy",
                               "账户资源策略无效");
            if (const auto ResultValue = AddId(Ids, Account.Id, Path + ".Id"); !ResultValue)
            {
                return ResultValue;
            }
            if (Account.SecretRef.empty() && Account.Credential.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "Credential or SecretRef is required");
            }
            if (!Account.SecretRef.empty())
            {
                if (const auto ResultValue = ValidateSecretReference(
                        Account.SecretRef, Path + ".SecretRef", Options);
                    !ResultValue)
                {
                    return ResultValue;
                }
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateRoutes(
        const PrismConfiguration &Configuration,
        std::unordered_set<std::string> &Ids) -> Result
    {
        for (std::size_t Index = 0; Index < Configuration.Routes.size(); ++Index)
        {
            const auto &Route = Configuration.Routes[Index];
            const auto Path = "Routes[" + std::to_string(Index) + "]";
            if (const auto ResultValue = AddId(Ids, Route.Id, Path + ".Id"); !ResultValue)
            {
                return ResultValue;
            }
            if (Route.Match.empty() || Route.Target.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "route Match and Target are required");
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateDnsAndPublicSettings(
        const PrismConfiguration &Configuration) -> Result
    {
        for (std::size_t Index = 0; Index < Configuration.Dns.Servers.size(); ++Index)
        {
            if (Configuration.Dns.Servers[Index].empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Dns.Servers[" + std::to_string(Index) + "]",
                               "DNS server must not be empty");
            }
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateTimeout(
                Configuration.Dns.Timeout, "Dns.Timeout");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateLogging(Configuration.Logging);
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateOperationsEndpoint(
                Configuration.Operations.Endpoint);
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateTimeout(
                Configuration.Statistics.Interval, "Statistics.Interval");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateTimeout(
                Configuration.Operations.Timeout, "Operations.Timeout");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = PublicSettingsValidator::ValidateTimeout(
                Configuration.HotReload.AckTimeout, "HotReload.AckTimeout");
            !ResultValue)
        {
            return ResultValue;
        }
        return PublicSettingsValidator::ValidateTimeout(
            Configuration.Shutdown.Timeout, "Shutdown.Timeout");
    }

} // namespace Prism::Application::Configuration::Validation
