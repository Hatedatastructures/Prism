/**
 * @file ProtocolProfile.hpp
 * @brief Prism TCP protocol candidate、认证 acceptor 和 recognition profile 装配。
 */

#pragma once
#include <Prism/Contract/Ingress/StreamFactory.hpp>

#include <Prism/Application/Application.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Application/Startup/StartupErrors.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Application/AccountCatalog.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Runtime/SessionServices.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Application::ProtocolProfile
{

    namespace Net = boost::asio;
    namespace Configuration = Prism::Application::Configuration;
    namespace Recognition = Prism::Composition::Recognition;
    namespace Core = Prism::Recognition;
    namespace Provider = Prism::Composition::Provider;
    /**
     * @brief TCP profile cold assembly 的借用服务上下文。
     * @details Configuration/Generation/ProviderBindings 仅在同步装配期间借用；返回的
     *          registry/profile/resolver 必须拥有其 callback、shared service 和 protocol owner，
     *          不得捕获本结构或内部引用到异步运行期。Datagrams/Streams/Dial 的 shared handles
     *          按值注入，executor 由其 service owner 提供。
     * @note 本上下文不执行 I/O、没有 cancellation/half-close；失败由 StartupError 映射，
     *       成功后的 acceptor/root/stream Close/Drain 归 protocol/runtime owner。
     */
    struct ProtocolFactoryContext final
    {
        const Configuration::PrismConfiguration& ConfigurationValue;
        const Configuration::ConfigurationGeneration& Generation;
        const AccountCatalog& Accounts;
        std::shared_ptr<Net::ssl::context> NativeTls;
        Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
        Provider::BoundCatalog* ProviderBindings{nullptr};
        Prism::Contract::DatagramServices Datagrams;
        Prism::Contract::StreamServices Streams;
    };

    [[nodiscard]] inline auto FindCarrier(const Configuration::PrismConfiguration& ConfigurationValue,
        const std::string_view CarrierId) noexcept -> const Prism::Contract::CarrierConfiguration*
    {
        const auto It = std::find_if(ConfigurationValue.Carriers.begin(), ConfigurationValue.Carriers.end(),
            [CarrierId](const auto& Carrier) { return Carrier.Id == CarrierId; });
        if (It == ConfigurationValue.Carriers.end())
        {
            return nullptr;
        }
        return &*It;
    }

    [[nodiscard]] inline auto ClampCandidatePriority(const std::int32_t Priority) noexcept -> std::uint16_t
    {
        if (Priority <= 0)
        {
            return 0;
        }
        return static_cast<std::uint16_t>((std::min)(Priority, 65535));
    }

    /**
     * @brief 一个 TCP binding 的 recognition 元数据借用视图。
     * @details string_view/span 只在同步 Append 调用期间有效；Append 复制这些值到
     *          RecognitionDefinition，不捕获配置地址到异步运行期。该值不拥有协议、网络
     *          或 executor，也没有取消、半关闭和最终关闭责任。
     */
    struct RecognitionCandidateSource final
    {
        std::string_view Scheme{};
        std::span<const std::string> ServerNames{};
        std::span<const std::string> Alpn{};
        std::uint16_t Priority{0};
        bool Fallback{false};
        std::string_view CarrierId{};
        std::string_view BindingId{};
        bool UdpEnabled{false};
    };

    /**
     * @class RecognitionCandidateAssembler
     * @brief 把配置 binding 转换为唯一的 cold candidate definition。
     * @details Result 由调用者拥有并借用到 assembler 销毁；Append 同步复制输入，失败只
     *          返回空 candidate id。该 assembler 不执行 I/O、不提供 cancellation/executor，
     *          也不拥有后续 acceptor、stream、半关闭或最终关闭。
     */
    class RecognitionCandidateAssembler final
    {
    public:
        explicit RecognitionCandidateAssembler(Recognition::RecognitionDefinition& Result)
            : Result_(Result)
        {
        }

        /**
         * @brief 追加一个配置 binding 并返回发布的 candidate id。
         * @param Configured 同步借用的 protocol configuration，不跨调用保存地址。
         * @param Source 同步借用的 scheme/name span；函数复制后立即结束借用。
         * @return 成功返回唯一 id；invalid id 或未知协议返回空值，无 typed 资源发布。
         * @note 纯 cold CPU 操作，无 I/O、取消、executor、stream half-close 或关闭者。
         */
        [[nodiscard]] auto Append(const Prism::Contract::ProtocolConfiguration& Configured,
            RecognitionCandidateSource Source) -> std::optional<Core::CandidateId>
        {
            if (NextId_ == Core::InvalidCandidate)
            {
                return std::nullopt;
            }
            const auto Protocol = Prism::Composition::Protocol::ProtocolCatalog::Find(Configured.Builtin);
            if (!Protocol || Protocol->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol ||
                !Protocol->SupportsTcp)
            {
                return std::nullopt;
            }
            Recognition::CandidateDefinition Candidate;
            Candidate.Id = NextId_;
            Candidate.Name = Configured.Id;
            Candidate.ProtocolId = Configured.Id;
            Candidate.Protocol = std::string(Protocol->Name);
            Candidate.Priority = Source.Priority;
            Candidate.Fallback = Source.Fallback;
            Candidate.Scheme = std::string(Source.Scheme);
            Candidate.ServerNames.assign(Source.ServerNames.begin(), Source.ServerNames.end());
            Candidate.Alpn.assign(Source.Alpn.begin(), Source.Alpn.end());
            Candidate.CarrierId = std::string(Source.CarrierId);
            Candidate.BindingId = std::string(Source.BindingId);
            Candidate.UdpEnabled = Source.UdpEnabled;
            if (!Source.Scheme.empty())
            {
                Candidate.Name += "+";
                Candidate.Name += Source.Scheme;
            }
            if (!Source.BindingId.empty())
            {
                Candidate.Name += "+";
                Candidate.Name += Source.BindingId;
            }
            Result_.Candidates.push_back(std::move(Candidate));
            const auto PublishedId = NextId_++;
            return PublishedId;
        }

    private:
        Recognition::RecognitionDefinition& Result_;
        Core::CandidateId NextId_{1};
    };

    [[nodiscard]] inline auto BindingRecognitionName(
        const Prism::Contract::RecognitionRouteConfiguration& Recognition) noexcept -> std::string_view
    {
        return std::string_view(Recognition.Pattern);
    }

    inline auto AppendBindingRecognitionRoute(Recognition::RecognitionDefinition& Result,
        const Prism::Contract::RecognitionRouteConfiguration& Recognition, const Core::CandidateId Candidate)
        -> void
    {
        const auto Name = BindingRecognitionName(Recognition);
        if (!Name.empty())
        {
            Result.Routes.emplace_back(std::string(Name), Candidate);
        }
    }

    /**
     * @brief 从冻结配置构造拥有型 TCP recognition definition。
     * @param ConfigurationValue 同步借用的 immutable configuration；输出不保存其地址。
     * @return 拥有候选、路由和预算值的 definition；无网络 I/O 或部分运行时资源。
     * @note 同步 cold assembly，无 cancellation/executor、stream half-close 或最终关闭者；
     *       后续 acceptor/root/stream 由正式 protocol/runtime owner 管理。
     */
    [[nodiscard]] inline auto MakeTcpRecognitionConfig(
        const Configuration::PrismConfiguration& ConfigurationValue)
        -> Recognition::RecognitionDefinition
    {
        Recognition::RecognitionDefinition Result;
        Result.Explicit = true;
        if (ConfigurationValue.Recognition.Mode == "Configured")
        {
            Result.Mode = Core::RecognitionMode::Configured;
        }
        else if (ConfigurationValue.Recognition.Mode == "Deterministic")
        {
            Result.Mode = Core::RecognitionMode::Deterministic;
        }
        else
        {
            Result.Mode = Core::RecognitionMode::MixedTrial;
        }
        if (ConfigurationValue.Recognition.ConfiguredCandidate >= 0)
        {
            Result.ConfiguredCandidate =
                static_cast<Core::CandidateId>(ConfigurationValue.Recognition.ConfiguredCandidate);
        }
        Result.Budget.MaxCandidates = static_cast<std::uint16_t>(Core::CandidateBitmap::Capacity);
        // Carrier bindings can add distinct TLS candidates for the same
        // protocol (for example native SS2022 alongside ShadowTLS).
        // Keep trial selection bounded, but leave enough room for the
        // explicit SNI route to reach its authenticated candidate.
        Result.Budget.MaxCryptoTrials = 16;
        auto CandidateCapacity = ConfigurationValue.ProtocolBindings.size();
        if (ConfigurationValue.ProtocolBindings.empty())
        {
            CandidateCapacity = ConfigurationValue.Protocols.size();
        }
        Result.Candidates.reserve(CandidateCapacity);
        RecognitionCandidateAssembler Candidates(Result);
        bool HasDefaultCandidate = false;
        std::uint16_t DefaultPriority = 0;
        const auto SelectDefault =
            [&](const Core::CandidateId Candidate, const std::uint16_t Priority, const bool IsDefault)
        {
            if (IsDefault && (!HasDefaultCandidate || Priority > DefaultPriority))
            {
                Result.DefaultCandidate = Candidate;
                DefaultPriority = Priority;
                HasDefaultCandidate = true;
            }
        };

        for (const auto& Configured : ConfigurationValue.Protocols)
        {
            if (ConfigurationValue.ProtocolBindings.empty())
            {
                (void)Candidates.Append(Configured, RecognitionCandidateSource{});
                continue;
            }

            bool HasTcpBinding = false;
            for (const auto& Binding : ConfigurationValue.ProtocolBindings)
            {
                if (Binding.ProtocolId != Configured.Id || !Binding.TcpEnabled)
                {
                    continue;
                }
                HasTcpBinding = true;
                if (!Binding.CarrierId)
                {
                    const auto Priority = ClampCandidatePriority(Binding.Priority);
                    const auto Candidate = Candidates.Append(Configured, RecognitionCandidateSource{
                        {}, {}, {}, Priority, Binding.Recognition.Fallback, {}, Binding.Id,
                        Binding.UdpEnabled});
                    if (Candidate)
                    {
                        AppendBindingRecognitionRoute(Result, Binding.Recognition, *Candidate);
                        SelectDefault(*Candidate, Priority, Binding.Recognition.Fallback);
                    }
                    continue;
                }
                const auto* Carrier = FindCarrier(ConfigurationValue, *Binding.CarrierId);
                if (Carrier == nullptr)
                {
                    continue;
                }
                const auto BindingRoute = BindingRecognitionName(Binding.Recognition);
                const auto BindingPriority = ClampCandidatePriority(Binding.Priority);
                const auto CarrierPriority = ClampCandidatePriority(Carrier->Match.Priority);
                const auto Priority = (std::max)(BindingPriority, CarrierPriority);
                const auto CarrierDescriptor =
                    Prism::Composition::Protocol::ProtocolCatalog::Find(Carrier->Builtin);
                const bool NativeFallback = CarrierDescriptor &&
                    CarrierDescriptor->Kind == Prism::Composition::Protocol::DescriptorKind::Carrier &&
                    CarrierDescriptor->Carrier == Prism::Composition::Protocol::CarrierKind::Native &&
                    Carrier->Match.ServerNames.empty() && Carrier->Match.Alpn.empty() &&
                    BindingRoute.empty() && !Binding.Recognition.Fallback;
                const auto Candidate = Candidates.Append(Configured, RecognitionCandidateSource{
                    Carrier->Builtin, Carrier->Match.ServerNames, Carrier->Match.Alpn, Priority,
                    Binding.Recognition.Fallback || Carrier->Match.Fallback || NativeFallback,
                    Carrier->Id, Binding.Id, Binding.UdpEnabled});
                if (Candidate)
                {
                    AppendBindingRecognitionRoute(Result, Binding.Recognition, *Candidate);
                    SelectDefault(*Candidate, Priority, Binding.Recognition.Fallback);
                }
            }
            if (!HasTcpBinding)
            {
                continue;
            }
        }
        return Result;
    }

} // namespace Prism::Application::ProtocolProfile
