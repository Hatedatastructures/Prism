/**
 * @file CandidateRegistry.hpp
 * @brief Settings 协议候选构造器注册表
 * @details Registry 只负责按配置中的协议名查找 Composition builder；具体
 *          凭据、carrier 和 handler 仍由注册时捕获的 builder 持有。注册表
 *          可复制出独立工厂，供 detached SessionFactory 脱离注册表对象继续使用。
 */

#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <preview/Composition/Recognition/CandidateFactory.hpp>
#include <preview/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <preview/Composition/Settings/Loader.hpp>

namespace Preview::Composition::Recognition
{

    /**
     * @brief 按 Settings 候选创建完整 Runtime binding
     */
    using SettingsCandidateFactory = std::function<std::optional<CandidateBinding>(
        const Preview::Settings::RecognitionCandidate &)>;

    namespace detail
    {

        [[nodiscard]] inline auto OptionsFrom(
            const Preview::Settings::RecognitionCandidate &Candidate) -> CandidateOptions
        {
            return CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority, Candidate.Tier,
                                     Candidate.Fallback};
        }

    } // namespace detail

    /**
     * @class CandidateRegistry
     * @brief 配置协议名到候选构造器的不可共享状态注册表
     * @details 注册只允许一次，避免后注册的 builder 静默改变已经审查过的
     *          配置语义。协议名按 ASCII 小写规范化，ss2022 与 shadowsocks
     *          作为同一个协议别名处理。带 Scheme 的候选必须同时注册 carrier
     *          接入回调，避免配置元数据看似生效但实际走明文 passthrough。
     */
    class CandidateRegistry
    {
    public:
        /**
         * @brief 注册协议候选构造器
         * @param Protocol 协议名
         * @param Builder 候选构造器
         * @return 名称合法且未重复注册时返回 true
         */
        [[nodiscard]] auto Register(std::string_view Protocol, SettingsCandidateFactory Builder) -> bool
        {
            const auto Name = Canonicalize(Protocol);
            if (Name.empty() || !Builder)
            {
                return false;
            }
            return Builders_.emplace(Name, std::move(Builder)).second;
        }

        /**
         * @brief 注册外层 carrier 接入回调
         * @param Scheme 外层方案名
         * @param Accept carrier 服务端接入回调
         * @return 名称合法且未重复注册时返回 true
         */
        [[nodiscard]] auto RegisterCarrier(std::string_view Scheme, CarrierAcceptFn Accept) -> bool
        {
            const auto Name = Normalize(Scheme);
            if (Name.empty() || !Accept)
            {
                return false;
            }
            return Carriers_.emplace(Name, std::move(Accept)).second;
        }

        /**
         * @brief 注册 HTTP CONNECT 候选构造器
         * @param Config HTTP 服务端配置
         * @return 注册成功返回 true
         */
        [[nodiscard]] auto RegisterHttp(HttpConfig Config = {}) -> bool
        {
            auto Shared = std::make_shared<const HttpConfig>(std::move(Config));
            return Register("http", [Shared](const auto &Candidate) -> std::optional<CandidateBinding>
                            { return CandidateFactory::MakeHttp(detail::OptionsFrom(Candidate), *Shared); });
        }

        /**
         * @brief 注册 SOCKS5 候选构造器
         * @param Config SOCKS5 服务端配置
         * @return 注册成功返回 true
         */
        [[nodiscard]] auto RegisterSocks5(Preview::Socks5::ServerConfig Config = {}) -> bool
        {
            auto Shared = std::make_shared<const Preview::Socks5::ServerConfig>(std::move(Config));
            return Register("socks5", [Shared](const auto &Candidate) -> std::optional<CandidateBinding>
                            { return CandidateFactory::MakeSocks5(detail::OptionsFrom(Candidate), *Shared); });
        }

        /**
         * @brief 注册 VLESS 候选构造器
         * @param Config VLESS 服务端配置
         * @return 注册成功返回 true
         */
        [[nodiscard]] auto RegisterVless(Preview::Vless::ServerConfig Config = {}) -> bool
        {
            auto Shared = std::make_shared<const Preview::Vless::ServerConfig>(std::move(Config));
            return Register("vless", [Shared](const auto &Candidate) -> std::optional<CandidateBinding>
                            { return CandidateFactory::MakeVless(detail::OptionsFrom(Candidate), *Shared); });
        }

        /**
         * @brief 注册 Trojan 候选构造器
         * @param Config Trojan 服务端配置
         * @return 注册成功返回 true
         */
        [[nodiscard]] auto RegisterTrojan(Preview::Trojan::ServerConfig Config = {}) -> bool
        {
            auto Shared = std::make_shared<const Preview::Trojan::ServerConfig>(std::move(Config));
            return Register("trojan", [Shared](const auto &Candidate) -> std::optional<CandidateBinding>
                            { return CandidateFactory::MakeTrojan(detail::OptionsFrom(Candidate), *Shared); });
        }

        /**
         * @brief 注册 VMess 候选构造器
         * @param Config VMess 服务端配置
         * @return 注册成功返回 true
         */
        [[nodiscard]] auto RegisterVmess(Preview::Vmess::ServerConfig Config = {}) -> bool
        {
            auto Shared = std::make_shared<const Preview::Vmess::ServerConfig>(std::move(Config));
            return Register("vmess", [Shared](const auto &Candidate) -> std::optional<CandidateBinding>
                            { return CandidateFactory::MakeVmess(detail::OptionsFrom(Candidate), *Shared); });
        }

        /**
         * @brief 注册 Shadowsocks 2022 候选构造器
         * @param Config SS2022 服务端配置
         * @return 注册成功返回 true
         */
        [[nodiscard]] auto RegisterSs2022(Preview::Shadowsocks2022::ServerConfig Config = {}) -> bool
        {
            auto Shared = std::make_shared<const Preview::Shadowsocks2022::ServerConfig>(std::move(Config));
            return Register("ss2022", [Shared](const auto &Candidate) -> std::optional<CandidateBinding>
                            { return CandidateFactory::MakeSs2022(detail::OptionsFrom(Candidate), *Shared); });
        }

        /**
         * @brief 查询协议是否已注册
         * @param Protocol 协议名
         * @return 已注册返回 true
         */
        [[nodiscard]] auto Has(std::string_view Protocol) const -> bool
        {
            return Find(Protocol) != nullptr;
        }

        /**
         * @brief 按配置候选创建 binding
         * @param Candidate 配置候选
         * @return builder 存在且构造成功时返回 binding
         */
        [[nodiscard]] auto Build(const Preview::Settings::RecognitionCandidate &Candidate) const
            -> std::optional<CandidateBinding>
        {
            return BuildFrom(Candidate, Builders_, Carriers_);
        }

        /**
         * @brief 创建独立的 Settings 工厂
         * @return 按值持有当前 builder 快照的工厂
         * @details 返回的工厂不借用当前 Registry，适合捕获到长期存活的
         *          listener/session factory 中。
         */
        [[nodiscard]] auto MakeFactory() const -> SettingsCandidateFactory
        {
            auto Builders = Builders_;
            auto Carriers = Carriers_;
            return [Builders = std::move(Builders), Carriers = std::move(Carriers)](
                       const Preview::Settings::RecognitionCandidate &Candidate)
                       -> std::optional<CandidateBinding>
            {
                return BuildFrom(Candidate, Builders, Carriers);
            };
        }

    private:
        [[nodiscard]] static auto BuildFrom(
            const Preview::Settings::RecognitionCandidate &Candidate,
            const std::unordered_map<std::string, SettingsCandidateFactory> &Builders,
            const std::unordered_map<std::string, CarrierAcceptFn> &Carriers)
            -> std::optional<CandidateBinding>
        {
            const auto Protocol = Canonicalize(Candidate.Protocol);
            const auto BuilderIt = Builders.find(Protocol);
            if (BuilderIt == Builders.end())
            {
                return std::nullopt;
            }
            auto Inner = BuilderIt->second(Candidate);
            if (!Inner)
            {
                return std::nullopt;
            }
            if (Candidate.Scheme.empty())
            {
                if (Inner->Spec.Kind == Core::CandidateKind::TlsCarrier &&
                    Normalize(Inner->Spec.Scheme).empty())
                {
                    return std::nullopt;
                }
                return Inner;
            }

            const auto Scheme = Normalize(Candidate.Scheme);
            if (Scheme.empty())
            {
                return std::nullopt;
            }
            if (Inner->Spec.Kind == Core::CandidateKind::TlsCarrier)
            {
                if (Normalize(Inner->Spec.Scheme) == Scheme)
                {
                    return Inner;
                }
                return std::nullopt;
            }
            const auto CarrierIt = Carriers.find(Scheme);
            if (CarrierIt == Carriers.end())
            {
                return std::nullopt;
            }

            TlsCandidateOptions Options;
            Options.Id = Candidate.Id;
            Options.Name = Candidate.Name;
            Options.Scheme = Scheme;
            Options.ServerNames = Candidate.ServerNames;
            Options.Alpn = Candidate.Alpn;
            Options.Fallback = Candidate.Fallback;
            return LayeredCandidateFactory::Make(std::move(Options), CarrierIt->second, std::move(*Inner));
        }

        [[nodiscard]] static auto Normalize(std::string_view Protocol) -> std::string
        {
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

        [[nodiscard]] static auto Canonicalize(std::string_view Protocol) -> std::string
        {
            auto Name = Normalize(Protocol);
            if (Name == "shadowsocks")
            {
                Name = "ss2022";
            }
            return Name;
        }

        [[nodiscard]] auto Find(std::string_view Protocol) const
            -> const SettingsCandidateFactory *
        {
            const auto Name = Canonicalize(Protocol);
            const auto It = Builders_.find(Name);
            if (It == Builders_.end())
            {
                return nullptr;
            }
            return &It->second;
        }

        std::unordered_map<std::string, SettingsCandidateFactory> Builders_;
        std::unordered_map<std::string, CarrierAcceptFn> Carriers_;
    };

} // namespace Preview::Composition::Recognition
