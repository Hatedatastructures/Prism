/**
 * @file OperationsConfiguration.hpp
 * @brief Operations 管理面安全配置视图与 secret-source 合并 owner。
 */
#pragma once

#include <Prism/Account/PolicyConfiguration.hpp>
#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Contract/Ingress/CarrierConfiguration.hpp>
#include <Prism/Application/Configuration/PrismConfigurationJson.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Operations/Models.hpp>

#include <glaze/glaze.hpp>

#include <cstddef>
#include <cstdint>
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

    [[nodiscard]] auto PublicView(const Configuration::PrismConfiguration &Source)
        -> PublicConfiguration;

    /** @brief 对同名现存账户与 QUIC protocol 保留当前代拥有的 inline secret。 */
    auto MergeExistingSecretSources(
        const Configuration::PrismConfiguration &Current,
        Configuration::PrismConfiguration &Candidate) -> void;

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

    [[nodiscard]] auto SerializePublicConfiguration(
        const Configuration::PrismConfiguration &Source)
        -> std::expected<std::string, Prism::Fault::Failure>;

} // namespace Prism::Application::OperationsConfiguration
