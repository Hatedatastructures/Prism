/**
 * @file PreviewConfiguration.hpp
 * @brief PrismPreview 的严格 PascalCase 配置模型。
 */
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace Preview::Application::Configuration
{

    struct ListenerEndpoint final
    {
        std::string Id;
        std::string Address{"0.0.0.0"};
        std::uint16_t Port{0};
        std::uint32_t Timeout{5000};
    };

    struct ListenersConfiguration final
    {
        std::vector<ListenerEndpoint> Tcp;
        std::vector<ListenerEndpoint> Udp;
        std::vector<ListenerEndpoint> Quic;
        std::uint32_t Timeout{5000};
    };

    struct NativeTlsConfiguration final
    {
        bool Enabled{false};
        std::string CertificateFile;
        std::string PrivateKeyFile;
    };

    struct NativeTlsOptions final
    {
        std::string CertificateFile;
        std::string PrivateKeyFile;
    };

    struct RealityOptions final
    {
        std::string HandshakeTarget;
        std::vector<std::string> ServerNames;
        std::string PrivateKeyRef;
        std::vector<std::string> ShortIds;
    };

    struct ShadowTlsOptions final
    {
        std::uint32_t Version{3};
        std::string PasswordSecretRef;
        std::string HandshakeDest;
        std::vector<std::string> ServerNames;
        bool StrictMode{true};
        std::uint32_t HandshakeTimeoutMs{5000};
    };

    struct RestlsOptions final
    {
        std::vector<std::string> ServerNames;
        std::string Host;
        std::string PasswordSecretRef;
        std::string VersionHint;
        std::string RestlsScript;
        std::uint32_t HandshakeTimeoutMs{5000};
    };

    struct WebSocketOptions final
    {
        std::string Path{ "/" };
        std::string Host;
    };

    struct XhttpOptions final
    {
        std::string Path{ "/" };
        std::string Host;
        std::string Mode{"StreamOne"};
    };

    struct GunOptions final
    {
        std::vector<std::string> ServerNames;
        std::string Mode{"GunLite"};
        std::string Path{"/GunService/Tun"};
        std::string ServiceName{"GunService"};
    };

    struct TrustTunnelOptions final
    {
        std::vector<std::string> ServerNames;
        std::string CertificateFile;
        std::string PrivateKeySecretRef;
        std::string PasswordSecretRef;
        std::string Network{"Both"};
        std::string Congestion{"Bbr"};
        std::uint32_t HandshakeTimeoutMs{5000};
        std::uint32_t IdleTimeoutMs{30000};
    };

    using CarrierOptions = std::variant<NativeTlsOptions,
                                        RealityOptions,
                                        ShadowTlsOptions,
                                        RestlsOptions,
                                        WebSocketOptions,
                                        XhttpOptions,
                                        GunOptions,
                                        TrustTunnelOptions>;

    struct CarrierMatchOptions final
    {
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        std::int32_t Priority{0};
        bool Fallback{false};
    };

    struct RuntimeConfiguration final
    {
        std::uint32_t WorkerCount{1};
        std::vector<std::string> RequiredCapabilities;
        std::uint32_t SessionTimeout{30000};
    };

    struct BuiltinConfiguration final
    {
        std::string Id;
        std::string Kind;
        std::string Name;
        std::vector<std::string> Requires;
        std::vector<std::string> Provides;
    };

    struct ProtocolConfiguration final
    {
        std::string Id;
        std::string Name;
        std::string Builtin;
        std::vector<std::string> Requires;
        struct QuicOptions final
        {
            std::string Alpn{"h3"};
            std::string ServerName;
            std::string CredentialSecretRef;
            std::uint32_t MaxStreams{64};
            std::uint32_t MaxDatagrams{64};
            std::string Uuid;
        };
        std::optional<QuicOptions> Quic;
    };

    struct RecognitionRouteConfiguration final
    {
        std::string Pattern;
        std::string Domain;
        bool Fallback{false};
    };

    struct ProtocolBindingConfiguration final
    {
        std::string Id;
        std::string ProtocolId;
        std::optional<std::string> CarrierId;
        bool TcpEnabled{true};
        bool UdpEnabled{false};
        std::vector<std::string> MuxModes;
        std::int32_t Priority{0};
        RecognitionRouteConfiguration Recognition{};
    };

    struct RecognitionConfiguration final
    {
        std::string Mode{"MixedTrial"};
        std::int32_t ConfiguredCandidate{-1};
    };

    struct CarrierConfiguration final
    {
        std::string Id;
        std::string Name;
        std::string Builtin;
        std::vector<std::string> Requires;
        CarrierMatchOptions Match{};
        CarrierOptions Options{};
    };

    struct AccountConfiguration final
    {
        std::string Id;
        std::string SecretRef;
        std::string Credential;
        std::map<std::string, std::string> Credentials;
    };

    struct RouteConfiguration final
    {
        std::string Id;
        std::string Match;
        std::string Target;
        std::vector<std::string> Requires;
    };

    struct DnsConfiguration final
    {
        std::vector<std::string> Servers;
        std::uint32_t Timeout{1000};
    };

    struct LoggingConfiguration final
    {
        std::string Level{"Info"};
        std::string Directory{"logs"};
        std::string FileName{"preview.log"};
        bool Console{false};
        std::uint64_t RotateBytes{64ULL * 1024ULL * 1024ULL};
        std::uint32_t RotateFiles{8};
        std::uint32_t FlushIntervalMs{250};
    };

    struct TraceConfiguration final
    {
        bool IncludeCorrelation{true};
        bool IncludeWorker{true};
        bool IncludeSession{true};
        bool IncludeStream{false};
    };

    struct StatisticsConfiguration final
    {
        bool Enabled{true};
        std::uint32_t Interval{1000};
    };

    struct OperationsConfiguration final
    {
        bool Enabled{true};
        std::string Endpoint{"127.0.0.1:9090"};
        std::uint32_t Timeout{1000};
    };

    struct HotReloadConfiguration final
    {
        bool Enabled{true};
        std::uint32_t AckTimeout{5000};
    };

    struct ShutdownConfiguration final
    {
        std::uint32_t Timeout{5000};
    };

    /** @brief Preview 应用完整配置；保持独立于生产配置模型。 */
    struct PreviewConfiguration final
    {
        std::uint32_t SchemaVersion{1};
        RuntimeConfiguration Runtime{};
        ListenersConfiguration Listeners{};
        NativeTlsConfiguration NativeTls{};
        std::vector<BuiltinConfiguration> Builtins;
        std::vector<ProtocolConfiguration> Protocols;
        std::vector<CarrierConfiguration> Carriers;
        std::vector<ProtocolBindingConfiguration> ProtocolBindings;
        RecognitionConfiguration Recognition{};
        std::vector<AccountConfiguration> Accounts;
        std::vector<RouteConfiguration> Routes;
        DnsConfiguration Dns{};
        LoggingConfiguration Logging{};
        TraceConfiguration Trace{};
        StatisticsConfiguration Statistics{};
        OperationsConfiguration Operations{};
        HotReloadConfiguration HotReload{};
        ShutdownConfiguration Shutdown{};

        [[nodiscard]] static auto Defaults() -> PreviewConfiguration
        {
            return {};
        }
    };

} // namespace Preview::Application::Configuration
