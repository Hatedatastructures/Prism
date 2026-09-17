/**
 * @file PreviewConfigurationJson.hpp
 * @brief PreviewConfiguration 的 glaze 映射。
 */
#pragma once

#include <Preview/Application/Configuration/PreviewConfiguration.hpp>

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
struct glz::meta<Preview::Application::Configuration::NativeTlsConfiguration>
{
    using T = Preview::Application::Configuration::NativeTlsConfiguration;
    static constexpr auto value = glz::object(
        "Enabled", &T::Enabled,
        "CertificateFile", &T::CertificateFile,
        "PrivateKeyFile", &T::PrivateKeyFile);
};

template <>
struct glz::meta<Preview::Application::Configuration::NativeTlsOptions>
{
    using T = Preview::Application::Configuration::NativeTlsOptions;
    static constexpr auto value = glz::object(
        "CertificateFile", &T::CertificateFile,
        "PrivateKeyFile", &T::PrivateKeyFile);
};

template <>
struct glz::meta<Preview::Application::Configuration::RealityOptions>
{
    using T = Preview::Application::Configuration::RealityOptions;
    static constexpr auto value = glz::object(
        "HandshakeTarget", &T::HandshakeTarget,
        "ServerNames", &T::ServerNames,
        "PrivateKeyRef", &T::PrivateKeyRef,
        "ShortIds", &T::ShortIds);
};

template <>
struct glz::meta<Preview::Application::Configuration::ShadowTlsOptions>
{
    using T = Preview::Application::Configuration::ShadowTlsOptions;
    static constexpr auto value = glz::object(
        "Version", &T::Version,
        "PasswordSecretRef", &T::PasswordSecretRef,
        "HandshakeDest", &T::HandshakeDest,
        "ServerNames", &T::ServerNames,
        "StrictMode", &T::StrictMode,
        "HandshakeTimeoutMs", &T::HandshakeTimeoutMs);
};

template <>
struct glz::meta<Preview::Application::Configuration::RestlsOptions>
{
    using T = Preview::Application::Configuration::RestlsOptions;
    static constexpr auto value = glz::object(
        "ServerNames", &T::ServerNames,
        "Host", &T::Host,
        "PasswordSecretRef", &T::PasswordSecretRef,
        "VersionHint", &T::VersionHint,
        "RestlsScript", &T::RestlsScript,
        "HandshakeTimeoutMs", &T::HandshakeTimeoutMs);
};

template <>
struct glz::meta<Preview::Application::Configuration::WebSocketOptions>
{
    using T = Preview::Application::Configuration::WebSocketOptions;
    static constexpr auto value = glz::object(
        "Path", &T::Path,
        "Host", &T::Host);
};

template <>
struct glz::meta<Preview::Application::Configuration::XhttpOptions>
{
    using T = Preview::Application::Configuration::XhttpOptions;
    static constexpr auto value = glz::object(
        "Path", &T::Path,
        "Host", &T::Host,
        "Mode", &T::Mode);
};

template <>
struct glz::meta<Preview::Application::Configuration::GunOptions>
{
    using T = Preview::Application::Configuration::GunOptions;
    static constexpr auto value = glz::object(
        "ServerNames", &T::ServerNames,
        "Mode", &T::Mode,
        "Path", &T::Path,
        "ServiceName", &T::ServiceName);
};

template <>
struct glz::meta<Preview::Application::Configuration::TrustTunnelOptions>
{
    using T = Preview::Application::Configuration::TrustTunnelOptions;
    static constexpr auto value = glz::object(
        "ServerNames", &T::ServerNames,
        "CertificateFile", &T::CertificateFile,
        "PrivateKeySecretRef", &T::PrivateKeySecretRef,
        "PasswordSecretRef", &T::PasswordSecretRef,
        "Network", &T::Network,
        "Congestion", &T::Congestion,
        "HandshakeTimeoutMs", &T::HandshakeTimeoutMs,
        "IdleTimeoutMs", &T::IdleTimeoutMs);
};

template <>
struct glz::meta<Preview::Application::Configuration::CarrierOptions>
{
    static constexpr std::string_view tag = "Type";
    static constexpr auto ids = std::array{
        "NativeTls",
        "Reality",
        "ShadowTls",
        "Restls",
        "WebSocket",
        "Xhttp",
        "Gun",
        "TrustTunnel"};
};

template <>
struct glz::meta<Preview::Application::Configuration::CarrierMatchOptions>
{
    using T = Preview::Application::Configuration::CarrierMatchOptions;
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
struct glz::meta<Preview::Application::Configuration::ProtocolConfiguration>
{
    using T = Preview::Application::Configuration::ProtocolConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Name", &T::Name,
        "Builtin", &T::Builtin,
        "Requires", &T::Requires,
        "Quic", &T::Quic);
};

template <>
struct glz::meta<Preview::Application::Configuration::ProtocolConfiguration::QuicOptions>
{
    using T = Preview::Application::Configuration::ProtocolConfiguration::QuicOptions;
    static constexpr auto value = glz::object(
        "Alpn", &T::Alpn,
        "ServerName", &T::ServerName,
        "CredentialSecretRef", &T::CredentialSecretRef,
        "MaxStreams", &T::MaxStreams,
        "MaxDatagrams", &T::MaxDatagrams,
        "Uuid", &T::Uuid);
};

template <>
struct glz::meta<Preview::Application::Configuration::RecognitionRouteConfiguration>
{
    using T = Preview::Application::Configuration::RecognitionRouteConfiguration;
    static constexpr auto value = glz::object(
        "Pattern", &T::Pattern,
        "Domain", &T::Domain,
        "Fallback", &T::Fallback);
};

template <>
struct glz::meta<Preview::Application::Configuration::ProtocolBindingConfiguration>
{
    using T = Preview::Application::Configuration::ProtocolBindingConfiguration;
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
struct glz::meta<Preview::Application::Configuration::CarrierConfiguration>
{
    using T = Preview::Application::Configuration::CarrierConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "Name", &T::Name,
        "Builtin", &T::Builtin,
        "Requires", &T::Requires,
        "Match", &T::Match,
        "Options", &T::Options);
};

template <>
struct glz::meta<Preview::Application::Configuration::AccountConfiguration>
{
    using T = Preview::Application::Configuration::AccountConfiguration;
    static constexpr auto value = glz::object(
        "Id", &T::Id,
        "SecretRef", &T::SecretRef,
        "Credential", &T::Credential,
        "Credentials", &T::Credentials);
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
        "Timeout", &T::Timeout);
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
        "Accounts", &T::Accounts,
        "Routes", &T::Routes,
        "Dns", &T::Dns,
        "Logging", &T::Logging,
        "Trace", &T::Trace,
        "Statistics", &T::Statistics,
        "Operations", &T::Operations,
        "HotReload", &T::HotReload,
        "Shutdown", &T::Shutdown);
};
