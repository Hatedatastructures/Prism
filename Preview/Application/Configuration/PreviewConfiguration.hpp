/**
 * @file PreviewConfiguration.hpp
 * @brief PrismPreview 的严格 PascalCase 配置模型。
 */
#pragma once
#include <Preview/Contract/Ingress/ProtocolConfiguration.hpp>
#include <Preview/Contract/Ingress/CarrierConfiguration.hpp>
#include <Preview/Account/PolicyConfiguration.hpp>

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
        struct EchServerConfiguration final
        {
            bool Enabled{false};
            std::string PrivateKeyFile;
            std::string EchConfigFile;
        } Ech;
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

    struct RecognitionConfiguration final
    {
        std::string Mode{"MixedTrial"};
        std::int32_t ConfiguredCandidate{-1};
    };

    /** @brief 配置文件中稳定、按字符串持久化的账户组 ID。 */
    using AccountGroupId = std::string;

    /** @brief 账户组仅提供稳定分类标识和显示名称，不承载继承策略。 */
    struct AccountGroupConfiguration final
    {
        AccountGroupId Id;
        std::string Name;
        Preview::Account::PolicyConfiguration Policy;
    };

    struct AccountConfiguration final
    {
        std::string Id;
        std::optional<AccountGroupId> GroupId;
        std::string SecretRef;
        std::string Credential;
        std::map<std::string, std::string> Credentials;
        Preview::Account::PolicyConfiguration Policy;
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
        std::string RenderMode{"CompactHuman"};
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
        std::optional<std::string> WebDirectory{}; ///< 未指定用宿主默认目录；空字符串禁用；相对路径相对配置文件。
    };

    /** @brief 空目录使用配置旁 data/配置名；显式路径按配置目录解析。 */
    struct StorageConfiguration final
    {
        std::string Directory;
        std::uint64_t HistoryMaxBytes{4ULL * 1024ULL * 1024ULL * 1024ULL};
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
        std::vector<Preview::Contract::ProtocolConfiguration> Protocols;
        std::vector<Preview::Contract::CarrierConfiguration> Carriers;
        std::vector<Preview::Contract::ProtocolBindingConfiguration> ProtocolBindings;
        RecognitionConfiguration Recognition{};
        std::vector<AccountGroupConfiguration> AccountGroups;
        std::vector<AccountConfiguration> Accounts;
        std::map<std::string, std::string> Secrets;
        std::vector<RouteConfiguration> Routes;
        DnsConfiguration Dns{};
        LoggingConfiguration Logging{};
        TraceConfiguration Trace{};
        StatisticsConfiguration Statistics{};
        OperationsConfiguration Operations{};
        StorageConfiguration Storage{};
        HotReloadConfiguration HotReload{};
        ShutdownConfiguration Shutdown{};

        [[nodiscard]] static auto Defaults() -> PreviewConfiguration
        {
            return {};
        }
    };

} // namespace Preview::Application::Configuration
