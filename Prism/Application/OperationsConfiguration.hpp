/**
 * @file OperationsConfiguration.hpp
 * @brief Operations 管理面安全配置视图与 secret-source 合并 owner。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationGeneration.hpp>
#include <Prism/Contract/Ingress/CarrierConfiguration.hpp>
#include <Prism/Application/Configuration/PrismConfigurationJson.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Operations/Models.hpp>

#include <glaze/glaze.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Application::OperationsConfiguration
{

    namespace Configuration = Prism::Application::Configuration;

    struct AccountReference final
    {
        std::string Id;
        std::string SecretRef;
        std::optional<Configuration::AccountGroupId> GroupId;
        Prism::Account::PolicyConfiguration Policy;
    };

    struct QuicReference final
    {
        std::string Alpn{"h3"};
        std::string ServerName;
        std::string CredentialSecretRef;
        std::uint32_t MaxStreams{64};
        std::uint32_t MaxDatagrams{64};
    };

    struct ProtocolReference final
    {
        std::string Id;
        std::string Name;
        std::string Builtin;
        std::vector<std::string> Requires;
        std::optional<QuicReference> Quic;
    };

    struct PublicConfiguration final
    {
        std::uint32_t SchemaVersion{1};
        Configuration::RuntimeConfiguration Runtime{};
        Configuration::ListenersConfiguration Listeners{};
        Configuration::NativeTlsConfiguration NativeTls{};
        std::vector<Configuration::BuiltinConfiguration> Builtins;
        std::vector<ProtocolReference> Protocols;
        std::vector<Prism::Contract::CarrierConfiguration> Carriers;
        std::vector<Prism::Contract::ProtocolBindingConfiguration> ProtocolBindings;
        Configuration::RecognitionConfiguration Recognition{};
        std::vector<Configuration::AccountGroupConfiguration> AccountGroups;
        std::vector<AccountReference> Accounts;
        std::vector<Configuration::RouteConfiguration> Routes;
        Configuration::DnsConfiguration Dns{};
        Configuration::LoggingConfiguration Logging{};
        Configuration::TraceConfiguration Trace{};
        Configuration::StatisticsConfiguration Statistics{};
        Configuration::OperationsConfiguration Operations{};
        Configuration::StorageConfiguration Storage{};
        Configuration::HotReloadConfiguration HotReload{};
        Configuration::ShutdownConfiguration Shutdown{};
    };

} // namespace Prism::Application::OperationsConfiguration

template <>
struct glz::meta<Prism::Application::OperationsConfiguration::AccountReference>;
template <>
struct glz::meta<Prism::Application::OperationsConfiguration::QuicReference>;
template <>
struct glz::meta<Prism::Application::OperationsConfiguration::ProtocolReference>;
template <>
struct glz::meta<Prism::Application::OperationsConfiguration::PublicConfiguration>;

namespace Prism::Application::OperationsConfiguration
{

    inline constexpr std::size_t MaxSafeConfigurationBytes{64U * 1024U};

    [[nodiscard]] inline auto PublicView(const Configuration::PrismConfiguration &Source)
        -> PublicConfiguration
    {
        PublicConfiguration Result;
        Result.SchemaVersion = Source.SchemaVersion;
        Result.Runtime = Source.Runtime;
        Result.Listeners = Source.Listeners;
        Result.NativeTls = Source.NativeTls;
        Result.Builtins = Source.Builtins;
        Result.Protocols.reserve(Source.Protocols.size());
        for (const auto &Protocol : Source.Protocols)
        {
            ProtocolReference Item;
            Item.Id = Protocol.Id;
            Item.Name = Protocol.Name;
            Item.Builtin = Protocol.Builtin;
            Item.Requires = Protocol.Requires;
            if (Protocol.Quic)
            {
                const auto &Quic = *Protocol.Quic;
                Item.Quic = QuicReference{
                    Quic.Alpn, Quic.ServerName, Quic.CredentialSecretRef,
                    Quic.MaxStreams, Quic.MaxDatagrams};
            }
            Result.Protocols.push_back(std::move(Item));
        }
        Result.Carriers = Source.Carriers;
        Result.ProtocolBindings = Source.ProtocolBindings;
        Result.Recognition = Source.Recognition;
        Result.AccountGroups = Source.AccountGroups;
        Result.Accounts.reserve(Source.Accounts.size());
        for (const auto &Account : Source.Accounts)
        {
            Result.Accounts.push_back(AccountReference{Account.Id, Account.SecretRef, Account.GroupId,
                                                       Account.Policy});
        }
        Result.Routes = Source.Routes;
        Result.Dns = Source.Dns;
        Result.Logging = Source.Logging;
        Result.Trace = Source.Trace;
        Result.Statistics = Source.Statistics;
        Result.Operations = Source.Operations;
        Result.Storage = Source.Storage;
        Result.HotReload = Source.HotReload;
        Result.Shutdown = Source.Shutdown;
        return Result;
    }

    /** @brief 对同名现存账户与 QUIC protocol 保留当前代拥有的 inline secret。 */
    inline auto MergeExistingSecretSources(
        const Configuration::PrismConfiguration &Current,
        Configuration::PrismConfiguration &Candidate) -> void
    {
        for (auto &Account : Candidate.Accounts)
        {
            if (!Account.SecretRef.empty()) continue;
            for (const auto &Existing : Current.Accounts)
            {
                if (Existing.Id != Account.Id) continue;
                Account.Credential = Existing.Credential;
                Account.Credentials = Existing.Credentials;
                break;
            }
        }
        for (auto &Protocol : Candidate.Protocols)
        {
            if (!Protocol.Quic || !Protocol.Quic->Uuid.empty()) continue;
            for (const auto &Existing : Current.Protocols)
            {
                if (Existing.Id != Protocol.Id || !Existing.Quic) continue;
                Protocol.Quic->Uuid = Existing.Quic->Uuid;
                break;
            }
        }
    }

} // namespace Prism::Application::OperationsConfiguration

template <>
struct glz::meta<Prism::Application::OperationsConfiguration::AccountReference>
{
    using T = Prism::Application::OperationsConfiguration::AccountReference;
    static constexpr auto value = glz::object("Id", &T::Id, "SecretRef", &T::SecretRef,
        "GroupId", &T::GroupId, "Policy", &T::Policy);
};

template <>
struct glz::meta<Prism::Application::OperationsConfiguration::QuicReference>
{
    using T = Prism::Application::OperationsConfiguration::QuicReference;
    static constexpr auto value = glz::object(
        "Alpn", &T::Alpn,
        "ServerName", &T::ServerName,
        "CredentialSecretRef", &T::CredentialSecretRef,
        "MaxStreams", &T::MaxStreams,
        "MaxDatagrams", &T::MaxDatagrams);
};

template <>
struct glz::meta<Prism::Application::OperationsConfiguration::ProtocolReference>
{
    using T = Prism::Application::OperationsConfiguration::ProtocolReference;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Name", &T::Name,
        "Builtin", &T::Builtin,
        "Requires", &T::Requires,
        "Quic", &T::Quic);
};

template <>
struct glz::meta<Prism::Application::OperationsConfiguration::PublicConfiguration>
{
    using T = Prism::Application::OperationsConfiguration::PublicConfiguration;
    static constexpr auto value = glz::object(
        "SchemaVersion", &T::SchemaVersion,
        "Runtime", &T::Runtime,
        "Listeners", &T::Listeners,
        "NativeTls", &T::NativeTls,
        "Builtins", &T::Builtins,
        "Protocols", &T::Protocols,
        "Carriers", &T::Carriers,
        "ProtocolBindings", &T::ProtocolBindings,
        "Recognition", &T::Recognition,
        "AccountGroups", &T::AccountGroups,
        "Accounts", &T::Accounts,
        "Routes", &T::Routes,
        "Dns", &T::Dns,
        "Logging", &T::Logging,
        "Trace", &T::Trace,
        "Statistics", &T::Statistics,
        "Operations", &T::Operations,
        "Storage", &T::Storage,
        "HotReload", &T::HotReload,
        "Shutdown", &T::Shutdown);
};

namespace Prism::Application::OperationsConfiguration
{

    [[nodiscard]] inline auto SerializePublicConfiguration(
        const Configuration::PrismConfiguration &Source)
        -> std::expected<std::string, Prism::Fault::Failure>
    {
        auto Json = glz::write_json(PublicView(Source));
        if (!Json)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ConfigErr});
        }
        if (Json->size() > MaxSafeConfigurationBytes)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        return std::move(*Json);
    }

    [[nodiscard]] inline auto MakeQuery(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        const Prism::Operations::ConfigurationQuery &Query)
        -> Prism::Operations::QueryResult
    {
        if (!State)
        {
            return Prism::Operations::QueryResult::Unavailable(Query.Correlation);
        }
        const auto Snapshot = State->ActiveGenerationSnapshot();
        if (!Snapshot || !Snapshot->Generation)
        {
            return Prism::Operations::QueryResult::Unavailable(Query.Correlation);
        }
        auto Json = SerializePublicConfiguration(Snapshot->Generation->Configuration());
        if (!Json)
        {
            auto Result = Prism::Operations::QueryResult::Unavailable(Query.Correlation);
            Result.Message = Json.error().Code == Prism::Fault::Code::ResourceUnavailable
                ? "configuration_snapshot_limit"
                : "configuration_snapshot_failed";
            return Result;
        }
        Prism::Operations::ConfigurationSnapshot Value;
        Value.Generation = Snapshot->Id();
        Value.Reloadable = Snapshot->Generation->Configuration().HotReload.Enabled;
        Value.Json = std::move(*Json);
        return Prism::Operations::QueryResult::Configuration(Query.Correlation, std::move(Value));
    }

} // namespace Prism::Application::OperationsConfiguration
