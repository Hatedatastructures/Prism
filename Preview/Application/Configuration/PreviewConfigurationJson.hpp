/**
 * @file PreviewConfigurationJson.hpp
 * @brief PreviewConfiguration 的 glaze 映射。
 */
#pragma once

#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Application/Configuration/AccountPolicyJson.hpp>

#include <array>

#include <glaze/glaze.hpp>

template <>
struct glz::meta<Preview::Application::Configuration::ListenerEndpoint>
{
    using T = Preview::Application::Configuration::ListenerEndpoint;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Address", &T::Address,
        "Port", &T::Port,
        "Timeout", &T::Timeout);
};

template <>
struct glz::meta<Preview::Application::Configuration::ListenersConfiguration>
{
    using T = Preview::Application::Configuration::ListenersConfiguration;
    static constexpr auto value = glz::object(
        "Tcp", &T::Tcp,
        "Udp", &T::Udp,
        "Quic", &T::Quic,
        "Timeout", &T::Timeout);
};

template <>
struct glz::meta<Preview::Application::Configuration::NativeTlsConfiguration::EchServerConfiguration>
{
    using T = Preview::Application::Configuration::NativeTlsConfiguration::EchServerConfiguration;
    static constexpr auto value = glz::object(
        "Enabled", &T::Enabled,
        "PrivateKeyFile", &T::PrivateKeyFile,
        "EchConfigFile", &T::EchConfigFile);
};

template <>
struct glz::meta<Preview::Application::Configuration::NativeTlsConfiguration>
{
    using T = Preview::Application::Configuration::NativeTlsConfiguration;
    static constexpr auto value = glz::object(
        "Enabled", &T::Enabled,
        "CertificateFile", &T::CertificateFile,
        "PrivateKeyFile", &T::PrivateKeyFile,
        "Ech", &T::Ech);
};

template <>
struct glz::meta<Preview::Contract::NativeTlsOptions>
{
    using T = Preview::Contract::NativeTlsOptions;
    static constexpr auto value = glz::object(
        "CertificateFile", &T::CertificateFile,
        "PrivateKeyFile", &T::PrivateKeyFile);
};

template <>
struct glz::meta<Preview::Contract::RealityOptions>
{
    using T = Preview::Contract::RealityOptions;
    static constexpr auto value = glz::object(
        "HandshakeTarget", &T::HandshakeTarget,
        "ServerNames", &T::ServerNames,
        "PrivateKeyRef", &T::PrivateKeyRef,
        "ShortIds", &T::ShortIds);
};

template <>
struct glz::meta<Preview::Contract::ShadowTlsOptions>
{
    using T = Preview::Contract::ShadowTlsOptions;
    static constexpr auto value = glz::object(
        "Version", &T::Version,
        "PasswordSecretRef", &T::PasswordSecretRef,
        "HandshakeDest", &T::HandshakeDest,
        "ServerNames", &T::ServerNames,
        "StrictMode", &T::StrictMode,
        "HandshakeTimeoutMs", &T::HandshakeTimeoutMs);
};

template <>
struct glz::meta<Preview::Contract::RestlsOptions>
{
    using T = Preview::Contract::RestlsOptions;
    static constexpr auto value = glz::object(
        "ServerNames", &T::ServerNames,
        "Host", &T::Host,
        "PasswordSecretRef", &T::PasswordSecretRef,
        "VersionHint", &T::VersionHint,
        "RestlsScript", &T::RestlsScript,
        "HandshakeTimeoutMs", &T::HandshakeTimeoutMs);
};

template <>
struct glz::meta<Preview::Contract::WebSocketOptions>
{
    using T = Preview::Contract::WebSocketOptions;
    static constexpr auto value = glz::object(
        "Path", &T::Path,
        "Host", &T::Host);
};

template <>
struct glz::meta<Preview::Contract::XhttpOptions>
{
    using T = Preview::Contract::XhttpOptions;
    static constexpr auto value = glz::object(
        "Path", &T::Path,
        "Host", &T::Host,
        "Mode", &T::Mode);
};

template <>
struct glz::meta<Preview::Contract::GunOptions>
{
    using T = Preview::Contract::GunOptions;
    static constexpr auto value = glz::object(
        "ServerNames", &T::ServerNames,
        "Mode", &T::Mode,
        "Path", &T::Path,
        "ServiceName", &T::ServiceName);
};

template <>
struct glz::meta<Preview::Contract::CarrierOptions>
{
    static constexpr std::string_view tag = "Type";
    static constexpr auto ids = std::array{
        "NativeTls",
        "Reality",
        "ShadowTls",
        "Restls",
        "WebSocket",
        "Xhttp",
        "Gun"};
};

template <>
struct glz::meta<Preview::Contract::CarrierMatchOptions>
{
    using T = Preview::Contract::CarrierMatchOptions;
    static constexpr auto value = glz::object(
        "ServerNames", &T::ServerNames,
        "Alpn", &T::Alpn,
        "Priority", &T::Priority,
        "Fallback", &T::Fallback);
};

template <>
struct glz::meta<Preview::Application::Configuration::RuntimeConfiguration>
{
    using T = Preview::Application::Configuration::RuntimeConfiguration;
    static constexpr auto value = glz::object(
        "WorkerCount", &T::WorkerCount,
        "RequiredCapabilities", &T::RequiredCapabilities,
        "SessionTimeout", &T::SessionTimeout);
};

template <>
struct glz::meta<Preview::Application::Configuration::BuiltinConfiguration>
{
    using T = Preview::Application::Configuration::BuiltinConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Kind", &T::Kind,
        "Name", &T::Name,
        "Requires", &T::Requires,
        "Provides", &T::Provides);
};

template <>
struct glz::meta<Preview::Contract::ProtocolConfiguration>
{
    using T = Preview::Contract::ProtocolConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Name", &T::Name,
        "Builtin", &T::Builtin,
        "Requires", &T::Requires,
        "Quic", &T::Quic);
};

template <>
struct glz::meta<Preview::Contract::ProtocolConfiguration::QuicOptions>
{
    using T = Preview::Contract::ProtocolConfiguration::QuicOptions;
    static constexpr auto value = glz::object(
        "Alpn", &T::Alpn,
        "ServerName", &T::ServerName,
        "CredentialSecretRef", &T::CredentialSecretRef,
        "MaxStreams", &T::MaxStreams,
        "MaxDatagrams", &T::MaxDatagrams,
        "Uuid", &T::Uuid);
};

template <>
struct glz::meta<Preview::Contract::RecognitionRouteConfiguration>
{
    using T = Preview::Contract::RecognitionRouteConfiguration;
    static constexpr auto value = glz::object(
        "Pattern", &T::Pattern,
        "Fallback", &T::Fallback);
};

template <>
struct glz::meta<Preview::Contract::ProtocolBindingConfiguration>
{
    using T = Preview::Contract::ProtocolBindingConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "ProtocolId", &T::ProtocolId,
        "CarrierId", &T::CarrierId,
        "TcpEnabled", &T::TcpEnabled,
        "UdpEnabled", &T::UdpEnabled,
        "MuxModes", &T::MuxModes,
        "Priority", &T::Priority,
        "Recognition", &T::Recognition);
};

template <>
struct glz::meta<Preview::Application::Configuration::RecognitionConfiguration>
{
    using T = Preview::Application::Configuration::RecognitionConfiguration;
    static constexpr auto value = glz::object(
        "Mode", &T::Mode,
        "ConfiguredCandidate", &T::ConfiguredCandidate);
};

template <>
struct glz::meta<Preview::Contract::CarrierConfiguration>
{
    using T = Preview::Contract::CarrierConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Name", &T::Name,
        "Builtin", &T::Builtin,
        "Requires", &T::Requires,
        "Match", &T::Match,
        "Options", &T::Options);
};

template <>
struct glz::meta<Preview::Application::Configuration::AccountGroupConfiguration>
{
    using T = Preview::Application::Configuration::AccountGroupConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Name", &T::Name,
        "Policy", &T::Policy);
};

template <>
struct glz::meta<Preview::Application::Configuration::AccountConfiguration>
{
    using T = Preview::Application::Configuration::AccountConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "GroupId", &T::GroupId,
        "SecretRef", &T::SecretRef,
        "Credential", &T::Credential,
        "Credentials", &T::Credentials,
        "Policy", &T::Policy);
};

template <>
struct glz::meta<Preview::Application::Configuration::RouteConfiguration>
{
    using T = Preview::Application::Configuration::RouteConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Match", &T::Match,
        "Target", &T::Target,
        "Requires", &T::Requires);
};

template <>
struct glz::meta<Preview::Application::Configuration::DnsConfiguration>
{
    using T = Preview::Application::Configuration::DnsConfiguration;
    static constexpr auto value = glz::object(
        "Servers", &T::Servers,
        "Timeout", &T::Timeout);
};

template <>
struct glz::meta<Preview::Application::Configuration::LoggingConfiguration>
{
    using T = Preview::Application::Configuration::LoggingConfiguration;
    static constexpr auto value = glz::object(
        "Level", &T::Level,
        "RenderMode", &T::RenderMode,
        "Directory", &T::Directory,
        "FileName", &T::FileName,
        "Console", &T::Console,
        "RotateBytes", &T::RotateBytes,
        "RotateFiles", &T::RotateFiles,
        "FlushIntervalMs", &T::FlushIntervalMs);
};

template <>
struct glz::meta<Preview::Application::Configuration::TraceConfiguration>
{
    using T = Preview::Application::Configuration::TraceConfiguration;
    static constexpr auto value = glz::object(
        "IncludeCorrelation", &T::IncludeCorrelation,
        "IncludeWorker", &T::IncludeWorker,
        "IncludeSession", &T::IncludeSession,
        "IncludeStream", &T::IncludeStream);
};

template <>
struct glz::meta<Preview::Application::Configuration::StatisticsConfiguration>
{
    using T = Preview::Application::Configuration::StatisticsConfiguration;
    static constexpr auto value = glz::object(
        "Enabled", &T::Enabled,
        "Interval", &T::Interval);
};

template <>
struct glz::meta<Preview::Application::Configuration::OperationsConfiguration>
{
    using T = Preview::Application::Configuration::OperationsConfiguration;
    static constexpr auto value = glz::object(
        "Enabled", &T::Enabled,
        "Endpoint", &T::Endpoint,
        "Timeout", &T::Timeout,
        "WebDirectory", &T::WebDirectory);
};

template <>
struct glz::meta<Preview::Application::Configuration::StorageConfiguration>
{
    using T = Preview::Application::Configuration::StorageConfiguration;
    static constexpr auto value = glz::object("Directory", &T::Directory,
        "HistoryMaxBytes", &T::HistoryMaxBytes);
};

template <>
struct glz::meta<Preview::Application::Configuration::HotReloadConfiguration>
{
    using T = Preview::Application::Configuration::HotReloadConfiguration;
    static constexpr auto value = glz::object(
        "Enabled", &T::Enabled,
        "AckTimeout", &T::AckTimeout);
};

template <>
struct glz::meta<Preview::Application::Configuration::ShutdownConfiguration>
{
    using T = Preview::Application::Configuration::ShutdownConfiguration;
    static constexpr auto value = glz::object("Timeout", &T::Timeout);
};

template <>
struct glz::meta<Preview::Application::Configuration::PreviewConfiguration>
{
    using T = Preview::Application::Configuration::PreviewConfiguration;
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
        "Secrets", &T::Secrets,
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
