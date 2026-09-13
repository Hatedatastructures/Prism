/**
 * @file SettingsBuilder.hpp
 * @brief Settings 配置到 recognition Profile 的 Composition 接线
 * @details Settings 只保存可序列化的候选元数据；具体凭据、handler 和 carrier
 *          由调用方提供 CandidateBinding 工厂。Profile 编译成功后才能安装到 Session。
 */

#pragma once

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <preview/Composition/Recognition/CandidateRegistry.hpp>
#include <preview/Composition/Recognition/ProfileBuilder.hpp>
#include <preview/Composition/Settings/Loader.hpp>
#include <preview/Runtime/Listener.hpp>

namespace Preview::Composition::Recognition
{

    namespace Core = Preview::Recognition;
    namespace Runtime = Preview::Runtime;

    namespace detail
    {

        [[nodiscard]] inline auto ParseProtocol(std::string_view Name)
            -> std::optional<Core::ProtocolType>
        {
            const auto Normalized = Preview::Settings::detail::NormalizeProtocol(Name);
            if (Normalized == "http")
            {
                return Core::ProtocolType::Http;
            }
            if (Normalized == "socks5")
            {
                return Core::ProtocolType::Socks5;
            }
            if (Normalized == "trojan")
            {
                return Core::ProtocolType::Trojan;
            }
            if (Normalized == "vless")
            {
                return Core::ProtocolType::Vless;
            }
            if (Normalized == "vmess")
            {
                return Core::ProtocolType::Vmess;
            }
            if (Normalized == "ss2022" || Normalized == "shadowsocks")
            {
                return Core::ProtocolType::Shadowsocks;
            }
            if (Normalized == "hysteria2")
            {
                return Core::ProtocolType::Hysteria2;
            }
            if (Normalized == "tuic")
            {
                return Core::ProtocolType::Tuic;
            }
            return std::nullopt;
        }

        [[nodiscard]] inline auto IsQuicProtocol(Core::ProtocolType Protocol) noexcept -> bool
        {
            return Protocol == Core::ProtocolType::Hysteria2 || Protocol == Core::ProtocolType::Tuic;
        }

        [[nodiscard]] inline auto WithRouteServerNames(
            const Preview::Settings::RecognitionConfig &Config,
            Preview::Settings::RecognitionCandidate Candidate)
            -> Preview::Settings::RecognitionCandidate
        {
            if (Candidate.Scheme.empty() || !Candidate.ServerNames.empty())
            {
                return Candidate;
            }
            for (const auto &Route : Config.Routes)
            {
                if (Route.Candidate != Candidate.Id)
                {
                    continue;
                }
                std::string_view Pattern = Route.Domain;
                if (!Route.Pattern.empty())
                {
                    Pattern = Route.Pattern;
                }
                if (!Pattern.empty() &&
                    std::find(Candidate.ServerNames.begin(), Candidate.ServerNames.end(), Pattern) ==
                        Candidate.ServerNames.end())
                {
                    Candidate.ServerNames.push_back(std::string(Pattern));
                }
            }
            return Candidate;
        }

        inline auto ApplySettingsMetadata(const Preview::Settings::RecognitionCandidate &Candidate,
                                          CandidateBinding &Binding) -> void
        {
            Binding.Spec.Id = Candidate.Id;
            if (!Candidate.Name.empty())
            {
                Binding.Spec.Name = Candidate.Name;
            }
            if (const auto Protocol = ParseProtocol(Candidate.Protocol))
            {
                Binding.Spec.Protocol = *Protocol;
            }
            const auto Scheme = Preview::Settings::detail::NormalizeScheme(Candidate.Scheme);
            if (!Scheme.empty())
            {
                Binding.Spec.Scheme = Scheme;
            }
            Binding.Spec.Priority = Candidate.Priority;
            Binding.Spec.Tier = Candidate.Tier;
            Binding.Spec.Fallback = Candidate.Fallback;
        }

    } // namespace detail

    /**
     * @brief 从 Settings 配置构建不可变 Profile 和候选 resolver
     * @param Config 已解析且尚未绑定 handler 的 recognition 配置
     * @param Factory 按候选配置创建 binding 的工厂
     * @return 成功时返回可安装到 SessionOptions 的 ProfileBuildResult
     */
    [[nodiscard]] inline auto BuildProfileFromSettings(
        const Preview::Settings::RecognitionConfig &Config,
        SettingsCandidateFactory Factory) -> std::expected<ProfileBuildResult, Core::ProfileError>
    {
        if (!Factory)
        {
            return std::unexpected(Core::ProfileError::MissingResolver);
        }

        std::vector<CandidateBinding> Bindings;
        Bindings.reserve(Config.Candidates.size());
        for (const auto &Candidate : Config.Candidates)
        {
            const auto Protocol = detail::ParseProtocol(Candidate.Protocol);
            if (!Protocol)
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            if (detail::IsQuicProtocol(*Protocol))
            {
                return std::unexpected(Core::ProfileError::QuicCandidateRequiresGateway);
            }
            auto Binding = Factory(detail::WithRouteServerNames(Config, Candidate));
            if (!Binding)
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            const auto Scheme = Preview::Settings::detail::NormalizeScheme(Candidate.Scheme);
            if (!Candidate.Scheme.empty() &&
                (Scheme.empty() || Binding->Spec.Kind != Core::CandidateKind::TlsCarrier ||
                 Preview::Settings::detail::NormalizeScheme(Binding->Spec.Scheme) != Scheme))
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            detail::ApplySettingsMetadata(Candidate, *Binding);
            Bindings.push_back(std::move(*Binding));
        }

        ProfileBuilderOptions Options;
        Options.Mode = Config.Mode;
        Options.ConfiguredCandidate = Config.ConfiguredCandidate;
        Options.DefaultCandidate = Config.DefaultCandidate;
        Options.Budget = Config.Budget;
        Options.Routes = Config.Routes;
        return ProfileBuilder::Build(std::move(Bindings), std::move(Options));
    }

    /**
     * @brief 使用注册表构建 recognition Profile
     * @param Config 已解析的 recognition 配置
     * @param Registry 协议候选构造器注册表
     * @return 成功时返回不可变 Profile 与 winner resolver
     */
    [[nodiscard]] inline auto BuildProfileFromSettings(
        const Preview::Settings::RecognitionConfig &Config, const CandidateRegistry &Registry)
        -> std::expected<ProfileBuildResult, Core::ProfileError>
    {
        return BuildProfileFromSettings(Config, Registry.MakeFactory());
    }

    /**
     * @brief 将构建结果成对安装到 SessionOptions
     * @param Options 会话选项
     * @param Result Profile 和 resolver 构建结果；函数取得其所有权
     * @return 构建结果有效并安装成功返回 true
     */
    [[nodiscard]] inline auto InstallProfile(Runtime::SessionOptions &Options,
                                              ProfileBuildResult Result) -> bool
    {
        if (!Result)
        {
            return false;
        }
        Options.Profile = std::move(Result.Profile);
        Options.ResolveCandidate = std::move(Result.Resolver);
        Options.Resolver = Options.ResolveCandidate;
        return true;
    }

    /**
     * @brief 从完整 ProxyConfig 构建带 recognition 的会话选项
     * @param Config 已通过 Settings::LoadConfig 校验的代理配置
     * @param Factory 按候选配置创建 binding 的工厂
     * @param Base 基础会话选项（拨号、中继和统计回调等）
     * @return 成功时返回已安装 Profile/resolver 的会话选项
     * @note 返回值可按值捕获到 TcpListener 的 SessionFactory，保证候选绑定与会话同寿命。
     */
    [[nodiscard]] inline auto BuildSessionOptionsFromSettings(
        const Preview::Settings::ProxyConfig &Config, SettingsCandidateFactory Factory,
        Runtime::SessionOptions Base = {}) -> std::expected<Runtime::SessionOptions, Core::ProfileError>
    {
        if (Config.AuthRequired && !Base.Auth)
        {
            return std::unexpected(Core::ProfileError::MissingAuthenticator);
        }
        auto Built = BuildProfileFromSettings(Config.Recognition, std::move(Factory));
        if (!Built)
        {
            return std::unexpected(Built.error());
        }
        if (!InstallProfile(Base, std::move(*Built)))
        {
            return std::unexpected(Core::ProfileError::MissingResolver);
        }
        constexpr auto MaxIdleTimeoutMs =
            static_cast<std::uint64_t>(std::chrono::milliseconds::max().count());
        if (Config.IdleTimeoutMs > MaxIdleTimeoutMs)
        {
            return std::unexpected(Core::ProfileError::InvalidTimeout);
        }
        Base.RelayIdleTimeout = std::chrono::milliseconds(
            static_cast<std::chrono::milliseconds::rep>(Config.IdleTimeoutMs));
        return Base;
    }

    /**
     * @brief 使用注册表构建带 recognition 的会话选项
     * @param Config 已解析的代理配置
     * @param Registry 协议候选构造器注册表
     * @param Base 基础会话选项
     * @return 成功时返回已安装 Profile/resolver 的会话选项
     */
    [[nodiscard]] inline auto BuildSessionOptionsFromSettings(
        const Preview::Settings::ProxyConfig &Config, const CandidateRegistry &Registry,
        Runtime::SessionOptions Base = {}) -> std::expected<Runtime::SessionOptions, Core::ProfileError>
    {
        return BuildSessionOptionsFromSettings(Config, Registry.MakeFactory(), std::move(Base));
    }

    /**
     * @brief 将会话选项封装为监听器可持有的 SessionFactory
     * @param Options 已完成 Profile/resolver 安装的会话选项
     * @return 按值共享会话配置的监听器工厂
     * @details 监听器和 detached 会话不借用调用方局部变量；每个 Session 取得独立选项副本，
     *          immutable Profile 与 resolver 通过 shared_ptr 继续存活。
     */
    [[nodiscard]] inline auto MakeSessionFactory(Runtime::SessionOptions Options)
        -> Runtime::TcpListener::SessionFactory
    {
        auto SharedOptions = std::make_shared<const Runtime::SessionOptions>(std::move(Options));
        return [SharedOptions](Preview::SharedTransmission, std::size_t)
            -> std::shared_ptr<Runtime::Session>
        {
            return std::make_shared<Runtime::Session>(*SharedOptions);
        };
    }

    /**
     * @brief 从配置直接创建监听器会话工厂
     * @param Config 已解析且尚未绑定 handler 的代理配置
     * @param Factory 按候选配置创建 binding 的工厂
     * @param Base 基础会话选项
     * @return 成功时返回可传给 TcpListener 的 SessionFactory
     */
    [[nodiscard]] inline auto BuildSessionFactoryFromSettings(
        const Preview::Settings::ProxyConfig &Config, SettingsCandidateFactory Factory,
        Runtime::SessionOptions Base = {})
        -> std::expected<Runtime::TcpListener::SessionFactory, Core::ProfileError>
    {
        auto Options = BuildSessionOptionsFromSettings(Config, std::move(Factory), std::move(Base));
        if (!Options)
        {
            return std::unexpected(Options.error());
        }
        return MakeSessionFactory(std::move(*Options));
    }

    /**
     * @brief 使用注册表创建监听器会话工厂
     * @param Config 已解析的代理配置
     * @param Registry 协议候选构造器注册表
     * @param Base 基础会话选项
     * @return 成功时返回可传给 TcpListener 的 SessionFactory
     */
    [[nodiscard]] inline auto BuildSessionFactoryFromSettings(
        const Preview::Settings::ProxyConfig &Config, const CandidateRegistry &Registry,
        Runtime::SessionOptions Base = {})
        -> std::expected<Runtime::TcpListener::SessionFactory, Core::ProfileError>
    {
        return BuildSessionFactoryFromSettings(Config, Registry.MakeFactory(), std::move(Base));
    }

    /**
     * @brief 将 Settings 的连接上限装配到 Preview TCP listener
     * @param Config 已解析的代理配置
     * @param Executor listener 使用的 Asio executor
     * @param Factory 已完成 Profile/resolver 接线的 SessionFactory
     * @param WorkerCount worker 亲和性桶数量
     * @return 带有 Settings.MaxConnections 上限的 listener
     * @note 监听地址和端口仍由调用方传给 TcpListener::Start。
     */
    [[nodiscard]] inline auto MakeTcpListenerFromSettings(
        const Preview::Settings::ProxyConfig &Config, boost::asio::any_io_executor Executor,
        Runtime::TcpListener::SessionFactory Factory, std::size_t WorkerCount = 1)
        -> Runtime::TcpListener
    {
        return Runtime::TcpListener(std::move(Executor), std::move(Factory), WorkerCount,
                                    Config.MaxConnections);
    }

    /**
     * @brief 按 Settings 的数值监听地址和端口启动 TCP listener
     * @param Config 已解析的代理配置
     * @param Listener 已装配 SessionFactory 的 listener
     * @return 启动结果；地址不是数值 IP 时返回 InvalidArgument
     * @note ListenAddr 只接受数值 IPv4/IPv6，避免启动阶段隐式 DNS 解析。
     */
    [[nodiscard]] inline auto StartTcpListenerFromSettings(
        const Preview::Settings::ProxyConfig &Config, Runtime::TcpListener &Listener)
        -> boost::asio::awaitable<Preview::Fault::Code>
    {
        boost::system::error_code Error;
        const auto Address = boost::asio::ip::make_address(Config.ListenAddr, Error);
        if (Error)
        {
            co_return Preview::Fault::Code::InvalidArgument;
        }
        co_return co_await Listener.Start(
            boost::asio::ip::tcp::endpoint(Address, Config.ListenPort));
    }

} // namespace Preview::Composition::Recognition
