/**
 * @file PrismConfiguration.hpp
 * @brief Prism 的严格 PascalCase 配置模型。
 */
#pragma once
#include <Prism/Foundation/Memory/BytePoolModels.hpp>
#include <Prism/Contract/Ingress/ProtocolConfiguration.hpp>
#include <Prism/Contract/Ingress/CarrierConfiguration.hpp>
#include <Prism/Account/PolicyConfiguration.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace Prism::Application::Configuration
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

    inline constexpr std::uint64_t BytePoolBlockBytes{64ULL * 1024ULL};
    inline constexpr std::uint64_t MaxBytePoolLimitBytes{16ULL * 1024ULL * 1024ULL * 1024ULL};

    /** @brief 进程和全部 worker 共用的按需增长内存池边界。 */
    struct BytePoolConfiguration final
    {
        std::uint64_t InitialBytes{4ULL * 1024ULL * 1024ULL};
        std::uint64_t GrowthBytes{4ULL * 1024ULL * 1024ULL};
        std::uint64_t LimitBytes{128ULL * 1024ULL * 1024ULL};
    };

    /** @brief 将已校验的字节配置转换为按固定块尺寸表达的运行时选项。 */
    [[nodiscard]] inline auto MakeBytePoolOptions(const BytePoolConfiguration &Configured) noexcept
        -> std::optional<Prism::Memory::BytePoolOptions>
    {
        constexpr auto BlockSize = Prism::Memory::BytePoolOptions{}.BlockSize;
        if (BlockSize == 0 || Configured.InitialBytes == 0 || Configured.GrowthBytes == 0 ||
            Configured.LimitBytes == 0 ||
            Configured.InitialBytes % BytePoolBlockBytes != 0 ||
            Configured.GrowthBytes % BytePoolBlockBytes != 0 ||
            Configured.LimitBytes % BytePoolBlockBytes != 0 ||
            Configured.InitialBytes > Configured.LimitBytes ||
            Configured.GrowthBytes > Configured.LimitBytes ||
            Configured.LimitBytes > MaxBytePoolLimitBytes ||
            Configured.LimitBytes > std::numeric_limits<std::size_t>::max())
        {
            return std::nullopt;
        }
        if (BytePoolBlockBytes != BlockSize)
        {
            return std::nullopt;
        }
        const auto LimitBlocks = Configured.LimitBytes / BytePoolBlockBytes;
        if (LimitBlocks > std::numeric_limits<std::size_t>::max())
        {
            return std::nullopt;
        }
        return Prism::Memory::BytePoolOptions{
            .BlockSize = BlockSize,
            .BlockCount = static_cast<std::size_t>(LimitBlocks),
            .InitialBlockCount =
                static_cast<std::size_t>(Configured.InitialBytes / BytePoolBlockBytes),
            .GrowthBlockCount =
                static_cast<std::size_t>(Configured.GrowthBytes / BytePoolBlockBytes)};
    }

    struct RuntimeConfiguration final
    {
        std::uint32_t WorkerCount{1};
        std::vector<std::string> RequiredCapabilities;
        std::uint32_t SessionTimeout{30000};
        /** @brief 进程级活动 TCP 会话上限；0 表示不限制。 */
        std::uint32_t MaxConnections{0};
        BytePoolConfiguration BytePool{};
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
        Prism::Account::PolicyConfiguration Policy;
    };

    struct AccountConfiguration final
    {
        std::string Id;
        std::optional<AccountGroupId> GroupId;
        std::string SecretRef;
        std::string Credential;
        std::map<std::string, std::string> Credentials;
        Prism::Account::PolicyConfiguration Policy;
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
        std::string FileName{"prism.log"};
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

    /** @brief Prism 应用完整配置；保持独立于生产配置模型。 */
    struct PrismConfiguration final
    {
        std::uint32_t SchemaVersion{1};
        RuntimeConfiguration Runtime{};
        ListenersConfiguration Listeners{};
        NativeTlsConfiguration NativeTls{};
        std::vector<BuiltinConfiguration> Builtins;
        std::vector<Prism::Contract::ProtocolConfiguration> Protocols;
        std::vector<Prism::Contract::CarrierConfiguration> Carriers;
        std::vector<Prism::Contract::ProtocolBindingConfiguration> ProtocolBindings;
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

        [[nodiscard]] static auto Defaults() -> PrismConfiguration
        {
            return {};
        }
    };

} // namespace Prism::Application::Configuration
