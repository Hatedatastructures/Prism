/**
 * @file Loader.hpp
 * @brief 配置加载与校验（T5-9）
 * @details JSON 配置 → 配置结构：
 *          - 必填字段缺失 → 校验失败
 *          - 类型错误 / 范围非法 → 校验失败
 *          - 未知字段忽略（向前兼容）
 * @note 自包含（Settings::json）；生产用 glaze loader
 */

#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <preview/Composition/Settings/Json.hpp>
#include <preview/Runtime/Recognition/Profile.hpp>

namespace Preview::Settings
{

    /**
     * @struct ConfigError
     * @brief 配置错误
     */
    struct ConfigError
    {
        std::string field{}; ///< 出错字段路径
        std::string Message{}; ///< 错误描述
    };

    /**
     * @struct RecognitionCandidate
     * @brief 配置层候选声明
     * @details 不包含协议 handler 或 Runtime 回调；由 Composition builder
     *          在启动阶段将其映射为 CandidateSpec。
     */
    struct RecognitionCandidate
    {
        Preview::Recognition::CandidateId Id{Preview::Recognition::InvalidCandidate};
        std::string Name;
        std::string Protocol;
        std::uint16_t Priority{0};
        std::uint8_t Tier{0};
        bool Fallback{false};
        std::string Scheme;
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
    };

    using RecognitionCandidateConfig = RecognitionCandidate;

    /**
     * @struct RecognitionConfig
     * @brief 多模式识别配置
     */
    struct RecognitionConfig
    {
        bool Explicit{false};
        Preview::Recognition::RecognitionMode Mode{Preview::Recognition::RecognitionMode::Configured};
        Preview::Recognition::CandidateId ConfiguredCandidate{Preview::Recognition::InvalidCandidate};
        Preview::Recognition::CandidateId DefaultCandidate{Preview::Recognition::InvalidCandidate};
        Preview::Recognition::RecognitionBudget Budget{};
        std::vector<RecognitionCandidate> Candidates;
        std::vector<Preview::Recognition::RouteBinding> Routes;
    };

    using RecognitionSettings = RecognitionConfig;

    /**
     * @struct ProxyConfig
     * @brief 代理配置（T5-9 示例结构）
     */
    struct ProxyConfig
    {
        std::string ListenAddr{"127.0.0.1"}; ///< 监听地址
        std::uint16_t ListenPort{0};         ///< 监听端口
        std::string Protocol{"socks5"};       ///< 入站协议
        std::uint32_t MaxConnections{1024};  ///< 最大连接数（0 = 无限制）
        bool AuthRequired{false};            ///< 是否强制认证
        std::uint64_t IdleTimeoutMs{60000}; ///< 空闲超时（毫秒）
        RecognitionConfig Recognition;       ///< 可选多模式识别配置
    };

    namespace detail
    {

        struct UnsignedRequest
        {
            const JsonValue &Value;
            std::uint64_t Minimum{0};
            std::uint64_t Maximum{0};
        };

        [[nodiscard]] inline auto ReadUnsigned(UnsignedRequest Request, std::uint64_t &Output) -> bool
        {
            if (Request.Value.Data.index() != 2)
            {
                return false;
            }
            const auto Number = std::get<double>(Request.Value.Data);
            const auto WideNumber = static_cast<long double>(Number);
            if (!std::isfinite(Number) || Number < static_cast<double>(Request.Minimum) ||
                WideNumber < static_cast<long double>(Request.Minimum) ||
                WideNumber > static_cast<long double>(Request.Maximum) ||
                std::floor(Number) != Number)
            {
                return false;
            }
            Output = static_cast<std::uint64_t>(Number);
            return true;
        }

        [[nodiscard]] inline auto NormalizeProtocol(std::string_view Protocol) -> std::string
        {
            if (Protocol.empty())
            {
                return {};
            }
            std::string Result;
            Result.reserve(Protocol.size());
            for (const auto Character : Protocol)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                const bool Letter = (Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z');
                const bool Digit = Byte >= '0' && Byte <= '9';
                if (!Letter && !Digit && Byte != '-' && Byte != '_')
                {
                    return {};
                }
                unsigned char Lower = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    Lower = static_cast<unsigned char>(Byte + ('a' - 'A'));
                }
                Result.push_back(static_cast<char>(Lower));
            }
            return Result;
        }

        [[nodiscard]] inline auto SupportedProtocol(std::string_view Protocol) -> bool
        {
            const auto Name = NormalizeProtocol(Protocol);
            return Name == "http" || Name == "socks5" || Name == "vless" || Name == "trojan" ||
                   Name == "vmess" || Name == "ss2022" || Name == "shadowsocks" ||
                   Name == "hysteria2" || Name == "tuic";
        }

        [[nodiscard]] inline auto Normalize(std::string_view Value) -> std::string
        {
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                unsigned char Lower = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    Lower = static_cast<unsigned char>(Byte + ('a' - 'A'));
                }
                Result.push_back(static_cast<char>(Lower));
            }
            while (!Result.empty() && Result.back() == '.')
            {
                Result.pop_back();
            }
            return Result;
        }

        [[nodiscard]] inline auto NormalizeScheme(std::string_view Value) -> std::string
        {
            if (Value.empty())
            {
                return {};
            }
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                const bool IsLetter = (Byte >= 'a' && Byte <= 'z') || (Byte >= 'A' && Byte <= 'Z');
                const bool IsDigit = Byte >= '0' && Byte <= '9';
                if (!IsLetter && !IsDigit && Byte != '-' && Byte != '_')
                {
                    return {};
                }
                unsigned char Lower = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    Lower = static_cast<unsigned char>(Byte + ('a' - 'A'));
                }
                Result.push_back(static_cast<char>(Lower));
            }
            return Result;
        }

        [[nodiscard]] inline auto ParseBudget(const std::map<std::string, JsonValue> &Object,
                                              RecognitionConfig &Config)
            -> ConfigError
        {
            const auto It = Object.find("Budget");
            if (It == Object.end())
            {
                return {};
            }
            if (It->second.Data.index() != 5)
            {
                return {"Recognition.Budget", "expected object"};
            }
            const auto &Budget = std::get<JsonObject>(It->second.Data).members;
            if (const auto Field = Budget.find("MaxProbeBytes"); Field != Budget.end())
            {
                std::uint64_t Value = 0;
                if (!ReadUnsigned(UnsignedRequest{Field->second, 1, 65536}, Value))
                {
                    return {"Recognition.Budget.MaxProbeBytes", "out of range or expected integer"};
                }
                Config.Budget.MaxProbeBytes = static_cast<std::size_t>(Value);
            }
            if (const auto Field = Budget.find("MaxCandidates"); Field != Budget.end())
            {
                std::uint64_t Value = 0;
                if (!ReadUnsigned(UnsignedRequest{Field->second, 1, 128}, Value))
                {
                    return {"Recognition.Budget.MaxCandidates", "out of range or expected integer"};
                }
                Config.Budget.MaxCandidates = static_cast<std::uint16_t>(Value);
            }
            if (const auto Field = Budget.find("MaxRoutes"); Field != Budget.end())
            {
                std::uint64_t Value = 0;
                if (!ReadUnsigned(UnsignedRequest{Field->second, 0, 4096}, Value))
                {
                    return {"Recognition.Budget.MaxRoutes", "out of range or expected integer"};
                }
                Config.Budget.MaxRoutes = static_cast<std::size_t>(Value);
            }
            if (const auto Field = Budget.find("MaxCandidateNameBytes"); Field != Budget.end())
            {
                std::uint64_t Value = 0;
                if (!ReadUnsigned(UnsignedRequest{Field->second, 1, 1024}, Value))
                {
                    return {"Recognition.Budget.MaxCandidateNameBytes",
                            "out of range or expected integer"};
                }
                Config.Budget.MaxCandidateNameBytes = static_cast<std::size_t>(Value);
            }
            if (const auto Field = Budget.find("MaxSchemeBytes"); Field != Budget.end())
            {
                std::uint64_t Value = 0;
                if (!ReadUnsigned(UnsignedRequest{Field->second, 1, 256}, Value))
                {
                    return {"Recognition.Budget.MaxSchemeBytes", "out of range or expected integer"};
                }
                Config.Budget.MaxSchemeBytes = static_cast<std::size_t>(Value);
            }
            if (const auto Field = Budget.find("MaxCryptoTrials"); Field != Budget.end())
            {
                std::uint64_t Value = 0;
                if (!ReadUnsigned(UnsignedRequest{Field->second, 0, 16}, Value))
                {
                    return {"Recognition.Budget.MaxCryptoTrials", "out of range or expected integer"};
                }
                Config.Budget.MaxCryptoTrials = static_cast<std::uint16_t>(Value);
            }
            const auto Timeout = Budget.find("TimeoutMs");
            const auto LegacyTimeout = Budget.find("Timeout");
            auto TimeoutIt = Timeout;
            if (TimeoutIt == Budget.end())
            {
                TimeoutIt = LegacyTimeout;
            }
            if (TimeoutIt != Budget.end())
            {
                std::uint64_t Value = 0;
                if (!ReadUnsigned(UnsignedRequest{
                                      TimeoutIt->second, 0,
                                      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())},
                                  Value))
                {
                    return {"Recognition.Budget.TimeoutMs", "out of range or expected integer"};
                }
                Config.Budget.Timeout = std::chrono::milliseconds(static_cast<std::int64_t>(Value));
            }
            return {};
        }

        [[nodiscard]] inline auto ParseStringList(const std::map<std::string, JsonValue> &Object,
                                                  std::string_view Field, std::string_view Path,
                                                  std::vector<std::string> &Output) -> ConfigError
        {
            const auto It = Object.find(std::string(Field));
            if (It == Object.end())
            {
                return {};
            }
            if (It->second.Data.index() != 4)
            {
                return {std::string(Path) + "." + std::string(Field), "expected array"};
            }
            const auto &Items = std::get<JsonArray>(It->second.Data).items;
            Output.reserve(Items.size());
            for (std::size_t Index = 0; Index < Items.size(); ++Index)
            {
                if (Items[Index].Data.index() != 3)
                {
                    return {std::string(Path) + "." + std::string(Field) + "[" + std::to_string(Index) + "]",
                            "expected string"};
                }
                const auto &Item = std::get<std::string>(Items[Index].Data);
                if (Item.empty())
                {
                    return {std::string(Path) + "." + std::string(Field) + "[" + std::to_string(Index) + "]",
                            "must not be empty"};
                }
                Output.push_back(Item);
            }
            return {};
        }

        [[nodiscard]] inline auto ParseCandidate(const JsonValue &Value, std::string_view Path,
                                                 RecognitionCandidate &Output) -> ConfigError
        {
            if (Value.Data.index() != 5)
            {
                return {std::string(Path), "expected object"};
            }
            const auto &Object = std::get<JsonObject>(Value.Data).members;
            const auto IdIt = Object.find("Id");
            if (IdIt == Object.end())
            {
                return {std::string(Path) + ".Id", "missing required field"};
            }
            std::uint64_t Id = 0;
            if (!ReadUnsigned(UnsignedRequest{IdIt->second, 0, 127}, Id))
            {
                return {std::string(Path) + ".Id", "out of range or expected integer"};
            }
            Output.Id = static_cast<Preview::Recognition::CandidateId>(Id);

            const auto ProtocolIt = Object.find("Protocol");
            if (ProtocolIt == Object.end() || ProtocolIt->second.Data.index() != 3)
            {
                return {std::string(Path) + ".Protocol", "missing or expected string"};
            }
            Output.Protocol = NormalizeProtocol(std::get<std::string>(ProtocolIt->second.Data));
            if (!SupportedProtocol(Output.Protocol))
            {
                return {std::string(Path) + ".Protocol", "unsupported protocol"};
            }

            Output.Name = Output.Protocol;
            if (const auto NameIt = Object.find("Name"); NameIt != Object.end())
            {
                if (NameIt->second.Data.index() != 3)
                {
                    return {std::string(Path) + ".Name", "expected string"};
                }
                Output.Name = std::get<std::string>(NameIt->second.Data);
            }
            if (Output.Name.empty())
            {
                return {std::string(Path) + ".Name", "must not be empty"};
            }

            if (const auto SchemeIt = Object.find("Scheme"); SchemeIt != Object.end())
            {
                if (SchemeIt->second.Data.index() != 3)
                {
                    return {std::string(Path) + ".Scheme", "expected string"};
                }
                Output.Scheme = NormalizeScheme(std::get<std::string>(SchemeIt->second.Data));
                if (Output.Scheme.empty())
                {
                    return {std::string(Path) + ".Scheme", "must be a non-empty ASCII scheme name"};
                }
            }
            if (const auto Error = ParseStringList(Object, "ServerNames", Path, Output.ServerNames);
                !Error.Message.empty())
            {
                return Error;
            }
            if (const auto Error = ParseStringList(Object, "Alpn", Path, Output.Alpn);
                !Error.Message.empty())
            {
                return Error;
            }
            if (Output.Scheme.empty() && (!Output.ServerNames.empty() || !Output.Alpn.empty()))
            {
                return {std::string(Path) + ".Scheme", "required when ServerNames or Alpn is configured"};
            }

            if (const auto PriorityIt = Object.find("Priority"); PriorityIt != Object.end())
            {
                std::uint64_t Priority = 0;
                if (!ReadUnsigned(UnsignedRequest{PriorityIt->second, 0, 65535}, Priority))
                {
                    return {std::string(Path) + ".Priority", "out of range or expected integer"};
                }
                Output.Priority = static_cast<std::uint16_t>(Priority);
            }
            if (const auto TierIt = Object.find("Tier"); TierIt != Object.end())
            {
                std::uint64_t Tier = 0;
                if (!ReadUnsigned(UnsignedRequest{TierIt->second, 0, 255}, Tier))
                {
                    return {std::string(Path) + ".Tier", "out of range or expected integer"};
                }
                Output.Tier = static_cast<std::uint8_t>(Tier);
            }
            if (const auto FallbackIt = Object.find("Fallback"); FallbackIt != Object.end())
            {
                if (FallbackIt->second.Data.index() != 1)
                {
                    return {std::string(Path) + ".Fallback", "expected bool"};
                }
                Output.Fallback = std::get<bool>(FallbackIt->second.Data);
            }
            return {};
        }

        [[nodiscard]] inline auto ParseCandidates(const std::map<std::string, JsonValue> &Object,
                                                  RecognitionConfig &Config)
            -> ConfigError
        {
            const auto It = Object.find("Candidates");
            if (It == Object.end())
            {
                return {"Recognition.Candidates", "missing required field"};
            }
            if (It->second.Data.index() != 4)
            {
                return {"Recognition.Candidates", "expected array"};
            }
            std::unordered_set<std::uint16_t> Ids;
            std::unordered_set<std::string> Names;
            const auto &Items = std::get<JsonArray>(It->second.Data).items;
            Config.Candidates.reserve(Items.size());
            for (std::size_t Index = 0; Index < Items.size(); ++Index)
            {
                RecognitionCandidate Candidate;
                const auto Path = std::string("Recognition.Candidates[") + std::to_string(Index) + "]";
                if (const auto Error = ParseCandidate(Items[Index], Path, Candidate); !Error.Message.empty())
                {
                    return Error;
                }
                if (!Ids.emplace(Candidate.Id).second)
                {
                    return {Path + ".Id", "duplicate candidate id"};
                }
                if (!Names.emplace(Candidate.Name).second)
                {
                    return {Path + ".Name", "duplicate candidate name"};
                }
                Config.Candidates.push_back(std::move(Candidate));
            }
            return {};
        }

        [[nodiscard]] inline auto ParseRoutes(const std::map<std::string, JsonValue> &Object,
                                              RecognitionConfig &Config)
            -> ConfigError
        {
            const auto It = Object.find("Routes");
            if (It == Object.end())
            {
                return {};
            }
            if (It->second.Data.index() != 4)
            {
                return {"Recognition.Routes", "expected array"};
            }
            std::unordered_set<std::string> Patterns;
            const auto &Items = std::get<JsonArray>(It->second.Data).items;
            Config.Routes.reserve(Items.size());
            for (std::size_t Index = 0; Index < Items.size(); ++Index)
            {
                const auto Path = std::string("Recognition.Routes[") + std::to_string(Index) + "]";
                if (Items[Index].Data.index() != 5)
                {
                    return {Path, "expected object"};
                }
                const auto &Route = std::get<JsonObject>(Items[Index].Data).members;
                const auto PatternIt = Route.find("Pattern");
                const auto DomainIt = Route.find("Domain");
                auto PatternValue = PatternIt;
                if (PatternValue == Route.end())
                {
                    PatternValue = DomainIt;
                }
                if (PatternValue == Route.end() || PatternValue->second.Data.index() != 3)
                {
                    return {Path + ".Pattern", "missing or expected string"};
                }
                const auto Pattern = std::get<std::string>(PatternValue->second.Data);
                const auto Normalized = Normalize(Pattern);
                if (Normalized.empty())
                {
                    return {Path + ".Pattern", "must not be empty"};
                }
                if (!Patterns.emplace(Normalized).second)
                {
                    return {Path + ".Pattern", "duplicate route"};
                }
                const auto CandidateIt = Route.find("Candidate");
                if (CandidateIt == Route.end())
                {
                    return {Path + ".Candidate", "missing required field"};
                }
                std::uint64_t Candidate = 0;
                if (!ReadUnsigned(UnsignedRequest{CandidateIt->second, 0, 127}, Candidate))
                {
                    return {Path + ".Candidate", "out of range or expected integer"};
                }
                const auto CandidateId = static_cast<Preview::Recognition::CandidateId>(Candidate);
                const auto Exists = std::any_of(Config.Candidates.begin(), Config.Candidates.end(),
                                                [CandidateId](const auto &Entry)
                                                { return Entry.Id == CandidateId; });
                if (!Exists)
                {
                    return {Path + ".Candidate", "dangling candidate"};
                }
                Config.Routes.emplace_back(Pattern, CandidateId);
            }
            return {};
        }

        [[nodiscard]] inline auto ParseRecognition(const JsonValue &Value, RecognitionConfig &Config)
            -> ConfigError
        {
            if (Value.Data.index() != 5)
            {
                return {"Recognition", "expected object"};
            }
            Config = RecognitionConfig{};
            Config.Explicit = true;
            const auto &Object = std::get<JsonObject>(Value.Data).members;
            if (const auto It = Object.find("Mode"); It != Object.end())
            {
                if (It->second.Data.index() != 3)
                {
                    return {"Recognition.Mode", "expected string"};
                }
                const auto &Mode = std::get<std::string>(It->second.Data);
                if (Mode == "Configured")
                {
                    Config.Mode = Preview::Recognition::RecognitionMode::Configured;
                }
                else if (Mode == "MixedTrial")
                {
                    Config.Mode = Preview::Recognition::RecognitionMode::MixedTrial;
                }
                else if (Mode == "Deterministic" || Mode == "DeterministicRoute")
                {
                    Config.Mode = Preview::Recognition::RecognitionMode::DeterministicRoute;
                }
                else
                {
                    return {"Recognition.Mode", "unknown mode"};
                }
            }
            if (const auto Error = ParseBudget(Object, Config); !Error.Message.empty())
            {
                return Error;
            }
            if (const auto Error = ParseCandidates(Object, Config); !Error.Message.empty())
            {
                return Error;
            }
            if (const auto It = Object.find("ConfiguredCandidate"); It != Object.end())
            {
                std::uint64_t Candidate = 0;
                if (!ReadUnsigned(UnsignedRequest{It->second, 0, 127}, Candidate))
                {
                    return {"Recognition.ConfiguredCandidate", "out of range or expected integer"};
                }
                Config.ConfiguredCandidate = static_cast<Preview::Recognition::CandidateId>(Candidate);
            }
            if (const auto It = Object.find("DefaultCandidate"); It != Object.end())
            {
                std::uint64_t Candidate = 0;
                if (!ReadUnsigned(UnsignedRequest{It->second, 0, 127}, Candidate))
                {
                    return {"Recognition.DefaultCandidate", "out of range or expected integer"};
                }
                Config.DefaultCandidate = static_cast<Preview::Recognition::CandidateId>(Candidate);
            }
            if (Config.Mode == Preview::Recognition::RecognitionMode::Configured)
            {
                if (Config.Candidates.size() != 1)
                {
                    return {"Recognition.Candidates", "Configured requires exactly one candidate"};
                }
                if (Config.ConfiguredCandidate == Preview::Recognition::InvalidCandidate)
                {
                    Config.ConfiguredCandidate = Config.Candidates.front().Id;
                }
            }
            else if (Config.Candidates.empty())
            {
                return {"Recognition.Candidates", "MixedTrial requires at least one candidate"};
            }
            if (Config.Mode == Preview::Recognition::RecognitionMode::MixedTrial &&
                Config.ConfiguredCandidate != Preview::Recognition::InvalidCandidate)
            {
                return {"Recognition.ConfiguredCandidate", "only valid in Configured mode"};
            }
            if (Config.Mode == Preview::Recognition::RecognitionMode::DeterministicRoute &&
                Config.ConfiguredCandidate != Preview::Recognition::InvalidCandidate)
            {
                return {"Recognition.ConfiguredCandidate", "not valid in DeterministicRoute mode"};
            }
            if (Config.ConfiguredCandidate != Preview::Recognition::InvalidCandidate)
            {
                const auto Exists = std::any_of(Config.Candidates.begin(), Config.Candidates.end(),
                                                [&Config](const auto &Candidate)
                                                { return Candidate.Id == Config.ConfiguredCandidate; });
                if (!Exists)
                {
                    return {"Recognition.ConfiguredCandidate", "dangling candidate"};
                }
            }
            if (Config.DefaultCandidate != Preview::Recognition::InvalidCandidate)
            {
                const auto Exists = std::any_of(Config.Candidates.begin(), Config.Candidates.end(),
                                                [&Config](const auto &Candidate)
                                                { return Candidate.Id == Config.DefaultCandidate; });
                if (!Exists)
                {
                    return {"Recognition.DefaultCandidate", "dangling candidate"};
                }
            }
            return ParseRoutes(Object, Config);
        }

    } // namespace detail

    /**
     * @brief 加载并校验配置
     * @param JsonText JSON 文本
     * @param out 输出配置
     * @return 空 = 成功；否则 ConfigError
     */
    [[nodiscard]] inline auto LoadConfig(std::string_view JsonText, ProxyConfig &out)
        -> ConfigError
    {
        out.ListenAddr = "127.0.0.1";
        out.ListenPort = 0;
        out.Protocol = "socks5";
        out.MaxConnections = 1024;
        out.AuthRequired = false;
        out.IdleTimeoutMs = 60000;
        out.Recognition = RecognitionConfig{};
        JsonValue root;
        const auto Jerr = ParseJson(JsonText, root);
        if (!Jerr.Message.empty())
        {
            return {"<root>", Jerr.Message};
        }
        if (root.Data.index() != 5)
        {
            return {"<root>", "expected object"};
        }

        const auto &obj = std::get<JsonObject>(root.Data).members;

        // ListenAddr（可选，字符串）
        if (const auto It = obj.find("ListenAddr"); It != obj.end())
        {
            if (It->second.Data.index() != 3)
            {
                return {"ListenAddr", "expected string"};
            }
            out.ListenAddr = std::get<std::string>(It->second.Data);
            if (out.ListenAddr.empty())
            {
                return {"ListenAddr", "Empty Address"};
            }
        }

        // ListenPort（必填，范围 1-65535）
        const auto PortIt = obj.find("ListenPort");
        if (PortIt == obj.end())
        {
            return {"ListenPort", "missing required field"};
        }
        std::uint64_t Port = 0;
        if (!detail::ReadUnsigned(detail::UnsignedRequest{PortIt->second, 1, 65535}, Port))
        {
            return {"ListenPort", "out of range or expected integer"};
        }
        out.ListenPort = static_cast<std::uint16_t>(Port);

        // Protocol（可选，字符串，枚举校验）
        if (const auto It = obj.find("Protocol"); It != obj.end())
        {
            if (It->second.Data.index() != 3)
            {
                return {"Protocol", "expected string"};
            }
            const auto proto = detail::NormalizeProtocol(std::get<std::string>(It->second.Data));
            if (!detail::SupportedProtocol(proto))
            {
                return {"Protocol", "unsupported Protocol"};
            }
            out.Protocol = proto;
        }

        // MaxConnections（可选，非负整数）
        if (const auto It = obj.find("MaxConnections"); It != obj.end())
        {
            std::uint64_t Mc = 0;
            if (!detail::ReadUnsigned(detail::UnsignedRequest{It->second, 0, 0xFFFFFFFFULL}, Mc))
            {
                return {"MaxConnections", "out of range or expected integer"};
            }
            out.MaxConnections = static_cast<std::uint32_t>(Mc);
        }

        // AuthRequired（可选，布尔）
        if (const auto It = obj.find("AuthRequired"); It != obj.end())
        {
            if (It->second.Data.index() != 1)
            {
                return {"AuthRequired", "expected bool"};
            }
            out.AuthRequired = std::get<bool>(It->second.Data);
        }

        // IdleTimeoutMs（可选，非负）
        if (const auto It = obj.find("IdleTimeoutMs"); It != obj.end())
        {
            std::uint64_t To = 0;
            if (!detail::ReadUnsigned(detail::UnsignedRequest{
                                          It->second, 0, std::numeric_limits<std::uint64_t>::max()},
                                      To))
            {
                return {"IdleTimeoutMs", "out of range or expected integer"};
            }
            out.IdleTimeoutMs = To;
        }

        if (const auto It = obj.find("Recognition"); It != obj.end())
        {
            return detail::ParseRecognition(It->second, out.Recognition);
        }

        // 旧格式保持兼容，同时显式生成唯一 Configured 候选。
        out.Recognition.Mode = Preview::Recognition::RecognitionMode::Configured;
        out.Recognition.ConfiguredCandidate = 0;
        out.Recognition.Candidates.push_back(
            RecognitionCandidate{0, out.Protocol, out.Protocol, 0, 0, false});
        return {};
    }

} // namespace Preview::Settings
