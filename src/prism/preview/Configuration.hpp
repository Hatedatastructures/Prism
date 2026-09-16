/**
 * @file Configuration.hpp
 * @brief PrismPreview 独立配置 wrapper 与命令行覆盖
 * @details 顶层字段与 src/configuration.json 保持同名语义，
 *          preview 节点只描述 Preview runtime 的显式模式和停机预算。
 *          生产 settings 转换后仍由 PSM validator 负责最终业务校验。
 */

#pragma once

#include <glaze/glaze.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <prism/settings/settings.hpp>

namespace psm::preview
{

    /**
     * @struct PreviewRuntimeConfig
     * @brief Preview runtime 的显式附加配置
     */
    struct PreviewRuntimeConfig
    {
        bool Enabled{true};
        bool Strict{true};
        bool Fallback{true};
        std::string Mode{"hybrid"};
        std::uint32_t ShutdownTimeoutMs{5000};
        std::uint32_t SessionDrainTimeoutMs{5000};
        bool EnableQuic{true};
    };

    /**
     * @enum RuntimeMode
     * @brief 已实现的 PrismPreview 数据面模式
     */
    enum class RuntimeMode : std::uint8_t
    {
        Hybrid,
        Socks5Preview,
        HttpPreview,
        ProductionFallback,
    };

    /**
     * @struct EffectiveRuntimeModes
     * @brief 启动阶段解析出的有效模式
     * @note Preview protocol adapters 当前尚未接入，始终明确为 false。
     */
    struct EffectiveRuntimeModes
    {
        RuntimeMode Mode{RuntimeMode::Hybrid};
        bool UsePreviewRuntime{true};
        bool UseProductionFallback{true};
        bool PreviewProtocolAdapters{false};
        bool EnableQuic{true};
    };

    /**
     * @struct CommandLine
     * @brief PrismPreview 命令行解析结果
     */
    struct CommandLine
    {
        std::filesystem::path ConfigPath;
        std::optional<std::string> ListenHost;
        std::optional<std::uint16_t> ListenPort;
    };

    /**
     * @struct Configuration
     * @brief 与 PSM 顶层 JSON 对齐的独立配置 wrapper
     */
    struct Configuration
    {
        std::uint32_t Version{1};
        psm::runtime::config Agent = []
        {
            psm::runtime::config Result;
            Result.addressable.host = "127.0.0.1";
            Result.addressable.port = 8081;
            return Result;
        }();
        psm::runtime::buffer Buffer{};
        psm::runtime::protocol::config Protocol{};
        psm::multiplex::config Multiplex{};
        psm::runtime::stealth::config Stealth{};
        psm::dns::config Dns{};
        psm::diagnose::config Trace{};
        PreviewRuntimeConfig Preview{};

        /**
         * @brief 获取默认配置对象
         */
        [[nodiscard]] static auto Defaults() -> Configuration
        {
            return {};
        }

        /**
         * @brief 将 wrapper 转为现有生产 settings
         */
        [[nodiscard]] auto ToProduction() const -> psm::settings
        {
            psm::settings Result;
            Result.version = Version;
            Result.instance = Agent;
            Result.buffer = Buffer;
            Result.protocol = Protocol;
            Result.mux = Multiplex;
            Result.stealth = Stealth;
            Result.dns = Dns;
            Result.trace = Trace;
            return Result;
        }

        /**
         * @brief 获取有效 runtime 模式
         */
        [[nodiscard]] auto EffectiveModes() const noexcept -> EffectiveRuntimeModes
        {
            if (Preview.Mode == "production_fallback")
            {
                return {RuntimeMode::ProductionFallback, false, true, false, Preview.EnableQuic};
            }
            if (Preview.Mode == "socks5_preview")
            {
                return {RuntimeMode::Socks5Preview, true, true, true, Preview.EnableQuic};
            }
            if (Preview.Mode == "http_preview")
            {
                return {RuntimeMode::HttpPreview, true, true, true, Preview.EnableQuic};
            }
            return {RuntimeMode::Hybrid, Preview.Enabled, Preview.Fallback || !Preview.Enabled, false,
                    Preview.EnableQuic};
        }

        /**
         * @brief 校验 wrapper 自身的严格约束
         * @return 空字符串表示通过
         */
        [[nodiscard]] auto Validate() const -> std::string
        {
            if (Version == 0)
            {
                return "version must be greater than zero";
            }
            if (Preview.Mode != "hybrid" && Preview.Mode != "socks5_preview" &&
                Preview.Mode != "http_preview" &&
                Preview.Mode != "production_fallback")
            {
                return "preview.mode must be hybrid, socks5_preview, http_preview, or production_fallback";
            }
            if (Preview.Strict && Agent.addressable.host != "127.0.0.1" &&
                Agent.addressable.host != "localhost" && Agent.addressable.host != "::1")
            {
                return "strict preview configuration requires a loopback listen host";
            }
            if (Agent.addressable.port == 0)
            {
                return "listen port must be greater than zero";
            }
            constexpr std::uint32_t MaxTimeoutMs = 600000;
            if (Preview.ShutdownTimeoutMs == 0 || Preview.ShutdownTimeoutMs > MaxTimeoutMs)
            {
                return "preview.shutdown_timeout_ms is outside the supported range";
            }
            if (Preview.SessionDrainTimeoutMs == 0 || Preview.SessionDrainTimeoutMs > MaxTimeoutMs)
            {
                return "preview.session_drain_timeout_ms is outside the supported range";
            }
            return {};
        }

        /**
         * @brief 严格解析 JSON
         * @param Json JSON 文本
         * @return 解析后的 wrapper 或错误描述
         * @details Glaze 默认 error_on_unknown_keys=true，未知顶层/preview
         *          字段会直接失败。
         */
        [[nodiscard]] static auto ParseJson(std::string_view Json)
            -> std::expected<Configuration, std::string>
        {
            glz::generic Document;
            if (const auto Error = glz::read_json(Document, Json); Error)
            {
                return std::unexpected("invalid PrismPreview JSON configuration");
            }
            if (!Document.is_object())
            {
                return std::unexpected("PrismPreview configuration must be a JSON object");
            }

            static constexpr std::array<std::string_view, 9> AllowedKeys = {
                "version", "agent", "buffer", "protocol", "multiplex", "stealth", "dns", "trace", "preview"};
            const auto &Object = Document.get_object();
            for (const auto &[Key, Value] : Object)
            {
                (void)Value;
                if (std::find(AllowedKeys.begin(), AllowedKeys.end(), Key) == AllowedKeys.end())
                {
                    return std::unexpected("unknown PrismPreview configuration key: " + Key);
                }
            }

            Configuration Result = Defaults();
            const auto ReadMember = [](const auto &Node, auto &Field) -> bool
            {
                const auto Dumped = Node.dump();
                if (!Dumped)
                {
                    return false;
                }
                return !glz::read_json(Field, *Dumped);
            };
            const auto ReadIfPresent = [&](const std::string_view Key, auto &Field) -> bool
            {
                const auto It = Object.find(Key);
                return It == Object.end() || ReadMember(It->second, Field);
            };

            if (!ReadIfPresent("version", Result.Version) ||
                !ReadIfPresent("agent", Result.Agent) ||
                !ReadIfPresent("buffer", Result.Buffer) ||
                !ReadIfPresent("protocol", Result.Protocol) ||
                !ReadIfPresent("multiplex", Result.Multiplex) ||
                !ReadIfPresent("stealth", Result.Stealth) ||
                !ReadIfPresent("dns", Result.Dns) ||
                !ReadIfPresent("trace", Result.Trace) ||
                !ReadIfPresent("preview", Result.Preview))
            {
                return std::unexpected("invalid PrismPreview configuration member");
            }
            if (const auto Error = Result.Validate(); !Error.empty())
            {
                return std::unexpected(Error);
            }
            return Result;
        }

        /**
         * @brief 从文件严格加载配置
         */
        [[nodiscard]] static auto LoadFile(const std::filesystem::path &Path)
            -> std::expected<Configuration, std::string>
        {
            std::ifstream File(Path, std::ios::binary);
            if (!File)
            {
                return std::unexpected("cannot open configuration file: " + Path.string());
            }
            const std::string Json((std::istreambuf_iterator<char>(File)),
                                   std::istreambuf_iterator<char>());
            return ParseJson(Json);
        }
    };

    /**
     * @brief 默认配置文件名
     */
    [[nodiscard]] inline auto DefaultConfigurationName() noexcept -> std::string_view
    {
        return "preview-configuration.json";
    }

    namespace detail
    {

        [[nodiscard]] inline auto ParsePort(std::string_view Value)
            -> std::expected<std::uint16_t, std::string>
        {
            if (Value.empty())
            {
                return std::unexpected("listen port is empty");
            }
            unsigned Parsed = 0;
            const auto *First = Value.data();
            const auto *Last = First + Value.size();
            const auto [End, Error] = std::from_chars(First, Last, Parsed);
            if (Error != std::errc{} || End != Last || Parsed == 0 || Parsed > 65535U)
            {
                return std::unexpected("listen port is invalid");
            }
            return static_cast<std::uint16_t>(Parsed);
        }

        [[nodiscard]] inline auto ParseListen(std::string_view Value)
            -> std::expected<std::pair<std::string, std::uint16_t>, std::string>
        {
            std::string_view Host;
            std::string_view Port;
            if (!Value.empty() && Value.front() == '[')
            {
                const auto Close = Value.find(']');
                if (Close == std::string_view::npos || Close + 2 > Value.size() || Value[Close + 1] != ':')
                {
                    return std::unexpected("listen endpoint must be host:port");
                }
                Host = Value.substr(1, Close - 1);
                Port = Value.substr(Close + 2);
            }
            else
            {
                const auto Colon = Value.rfind(':');
                if (Colon == std::string_view::npos || Value.find(':') != Colon)
                {
                    return std::unexpected("listen endpoint must be host:port");
                }
                Host = Value.substr(0, Colon);
                Port = Value.substr(Colon + 1);
            }
            if (Host.empty())
            {
                return std::unexpected("listen host is empty");
            }
            auto ParsedPort = ParsePort(Port);
            if (!ParsedPort)
            {
                return std::unexpected(ParsedPort.error());
            }
            return std::pair{std::string(Host), *ParsedPort};
        }

    } // namespace detail

    /**
     * @brief 解析 PrismPreview 命令行
     * @details 支持首个 positional config path，以及 --config PATH 和
     *          --listen HOST:PORT；未知参数直接失败。
     */
    [[nodiscard]] inline auto ParseCommandLine(int Argc, char *Argv[], std::filesystem::path DefaultPath)
        -> std::expected<CommandLine, std::string>
    {
        CommandLine Result;
        Result.ConfigPath = std::move(DefaultPath);
        bool ExplicitConfig = false;
        for (int Index = 1; Index < Argc; ++Index)
        {
            const std::string_view Argument = Argv[Index] ? Argv[Index] : "";
            auto ReadValue = [&](std::string_view Name) -> std::expected<std::string_view, std::string>
            {
                if (Argument == Name)
                {
                    if (Index + 1 >= Argc)
                    {
                        return std::unexpected(std::string(Name) + " requires a value");
                    }
                    return std::string_view(Argv[++Index]);
                }
                const std::string Prefix = std::string(Name) + "=";
                if (Argument.starts_with(Prefix))
                {
                    return Argument.substr(Prefix.size());
                }
                return std::unexpected("");
            };

            if (Argument == "--config" || Argument.starts_with("--config="))
            {
                auto Value = ReadValue("--config");
                if (!Value || Value->empty())
                {
                    return std::unexpected(Value ? "--config requires a value" : Value.error());
                }
                if (ExplicitConfig)
                {
                    return std::unexpected("configuration path specified more than once");
                }
                ExplicitConfig = true;
                Result.ConfigPath = std::filesystem::path(*Value);
                continue;
            }
            if (Argument == "--listen" || Argument.starts_with("--listen="))
            {
                auto Value = ReadValue("--listen");
                if (!Value)
                {
                    return std::unexpected(Value.error());
                }
                auto Endpoint = detail::ParseListen(*Value);
                if (!Endpoint)
                {
                    return std::unexpected(Endpoint.error());
                }
                Result.ListenHost = Endpoint->first;
                Result.ListenPort = Endpoint->second;
                continue;
            }
            if (Argument.starts_with('-'))
            {
                return std::unexpected("unknown command-line option: " + std::string(Argument));
            }
            if (ExplicitConfig)
            {
                return std::unexpected("configuration path specified more than once");
            }
            ExplicitConfig = true;
            Result.ConfigPath = std::filesystem::path(Argument);
        }
        return Result;
    }

    /**
     * @brief 应用命令行覆盖
     */
    inline auto ApplyCommandLineOverrides(Configuration &Config, const CommandLine &Command) -> bool
    {
        if (Command.ListenHost)
        {
            Config.Agent.addressable.host = *Command.ListenHost;
        }
        if (Command.ListenPort)
        {
            Config.Agent.addressable.port = *Command.ListenPort;
        }
        return true;
    }

} // namespace psm::preview

template <>
struct glz::meta<psm::preview::PreviewRuntimeConfig>
{
    using T = psm::preview::PreviewRuntimeConfig;
    static constexpr auto value = glz::object(
        "enabled", &T::Enabled,
        "strict", &T::Strict,
        "fallback", &T::Fallback,
        "mode", &T::Mode,
        "shutdown_timeout_ms", &T::ShutdownTimeoutMs,
        "session_drain_timeout_ms", &T::SessionDrainTimeoutMs,
        "enable_quic", &T::EnableQuic);
};

template <>
struct glz::meta<psm::preview::Configuration>
{
    using T = psm::preview::Configuration;
    static constexpr auto value = glz::object(
        "version", &T::Version,
        "agent", &T::Agent,
        "buffer", &T::Buffer,
        "protocol", &T::Protocol,
        "multiplex", &T::Multiplex,
        "stealth", &T::Stealth,
        "dns", &T::Dns,
        "trace", &T::Trace,
        "preview", &T::Preview);
};
