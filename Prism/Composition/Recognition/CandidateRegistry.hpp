/**
 * @file CandidateRegistry.hpp
 * @brief Prism 配置协议候选构造器注册表
 * @details Registry 只负责按配置中的协议名查找 Composition builder；具体
 *          凭据、carrier 和 handler 仍由注册时捕获的 builder 持有。注册表
 *          可复制出独立工厂，供 detached SessionFactory 脱离注册表对象继续使用。
 */

#pragma once

#include <functional>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Prism/Composition/Recognition/TrusttunnelCandidate.hpp>
#include <Prism/Composition/Recognition/TlsCarrierHelpers.hpp>
#include <Prism/Composition/Recognition/ShadowtlsCarrier.hpp>
#include <Prism/Composition/Recognition/RestlsCarrier.hpp>
#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

namespace Prism::Composition::Recognition
{

    /**
     * @brief 按 Prism 配置候选创建完整 Runtime binding
     */
    namespace detail
    {

        [[nodiscard]] inline auto CanonicalCarrierScheme(std::string_view Scheme) -> std::string
        {
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Scheme);
            if (Descriptor && (Descriptor->Kind == Prism::Composition::Protocol::DescriptorKind::Carrier ||
                               Descriptor->Id == Prism::Contract::ProtocolType::TrustTunnel))
                return std::string(Descriptor->Name);
            return std::string(Scheme);
        }

        [[nodiscard]] inline auto CarrierForScheme(std::string_view Scheme)
            -> std::optional<TlsCarrier>
        {
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Scheme);
            if (!Descriptor) return std::nullopt;
            if (Descriptor->Kind == Prism::Composition::Protocol::DescriptorKind::Carrier)
                return Descriptor->Carrier;
            if (Descriptor->Id == Prism::Contract::ProtocolType::TrustTunnel)
                return TlsCarrier::TrustTunnel;
            return std::nullopt;
        }

        [[nodiscard]] inline auto OptionsFrom(
            const CandidateDefinition &Candidate) -> CandidateOptions
        {
            CandidateOptions Options;
            Options.Id = Candidate.Id;
            Options.Name = Candidate.Name;
            Options.Priority = Candidate.Priority;
            Options.Tier = Candidate.Tier;
            Options.Fallback = Candidate.Fallback;
            Options.BindingId = Candidate.BindingId;
            Options.UdpEnabled = Candidate.UdpEnabled;
            return Options;
        }

    } // namespace detail

    /**
     * @class CandidateRegistry
     * @brief 配置协议名到候选构造器的不可共享状态注册表
     * @details 注册只允许一次，避免后注册的 builder 静默改变已经审查过的
     *          配置语义。协议名按 ASCII 小写规范化，不将历史名称映射到内建协议。
     *          带 Scheme 的候选必须同时注册 carrier
     *          接入回调，避免配置元数据看似生效但实际走明文 passthrough。
     */
    class CandidateRegistry
    {
    public:
        struct CarrierRegistration final
        {
            Prism::Composition::Protocol::ProviderKey Key;
            CarrierAcceptFn Accept;
            CarrierAcceptPreparedFn AcceptPrepared;
            /** @brief TLS accept callback 实际捕获并保活 Native SSL_CTX。 */
            bool HasNativeTlsContext{false};
        };

    private:
        struct BuilderState final
        {
            std::unordered_map<std::string, CandidateBuilder> Builders;
            std::unordered_map<std::string, CarrierRegistration> Carriers;
            std::unordered_map<std::string, CarrierRegistration> CarriersById;
        };

    public:

        /**
         * @brief 注册协议候选构造器
         * @param Protocol 协议名
         * @param Builder 候选构造器
         * @return 名称合法且未重复注册时返回 true
         */
        [[nodiscard]] auto Register(std::string_view Protocol, CandidateBuilder Builder) -> bool
        {
            const auto Name = Canonicalize(Protocol);
            if (Name.empty() || !Builder)
            {
                return false;
            }
            return State_.Builders.emplace(Name, std::move(Builder)).second;
        }

        /**
         * @brief 将一个已绑定的 typed TLS carrier 放入候选工厂目录。
         * @param Key 必须命中 ProtocolCatalog 中真实 DescriptorKind::Carrier 的 typed 槽位。
         * @param Id 空值表示默认 scheme，非空值表示本配置 carrier instance。
         * @param Registration 按值接管的唯一普通或 prepared 接入回调。
         * @return 唯一注册成功；重复 ID/key、类别不符或回调形状无效时返回 false。
         */
        [[nodiscard]] auto RegisterTlsCarrier(
            Prism::Composition::Protocol::ProviderKey Key,
            std::string Id,
            CarrierRegistration Registration) -> bool
        {
            using Category = Prism::Composition::Protocol::ProviderCategory;
            const auto *Kind = std::get_if<Prism::Composition::Protocol::CarrierKind>(&Key.Identity);
            if (Key.Category != Category::TlsCarrier || Kind == nullptr ||
                (*Kind == Prism::Composition::Protocol::CarrierKind::None) ||
                (static_cast<bool>(Registration.Accept) == static_cast<bool>(Registration.AcceptPrepared)))
            {
                return false;
            }
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Key);
            if (!Descriptor || Descriptor->Kind !=
                    Prism::Composition::Protocol::DescriptorKind::Carrier)
            {
                return false;
            }
            const auto Scheme = Descriptor->Name;
            Registration.Key = Key;
            if (Id.empty())
            {
                return State_.Carriers.emplace(std::string(Scheme), std::move(Registration)).second;
            }
            const auto CarrierId = Normalize(Id);
            if (CarrierId.empty())
            {
                return false;
            }
            return State_.CarriersById.emplace(CarrierId, std::move(Registration)).second;
        }

        /**
         * @brief 为一个 configured instance 注册唯一 cold candidate builder。
         * @param Id 配置实例 ID；BuildFrom 以 instance/Id 冷查找，不进入热路径。
         * @param Builder 按候选元数据生成 owning CandidateBinding；返回值拥有唯一 Accept。
         * @return ID 合法、builder 非空且此前未注册时为 true。
         * @note 注册只在 profile 冷构造阶段发生；发布后 factory 不再动态查名或改写。
         */
        [[nodiscard]] auto RegisterConfigured(std::string Id, CandidateBuilder Builder) -> bool
        {
            if (Id.empty() || !Builder)
            {
                return false;
            }
            return State_.Builders.emplace("instance/" + std::move(Id), std::move(Builder)).second;
        }

        /**
         * @brief 登记 provider 的唯一冷候选构造器，输入按值进入不可变 factory 快照。
         * @return ID 合法、builder 尚未登记时为 true；分配异常直接传播。
         * @note 同步注册没有 I/O、取消或半关闭；发布后的 binding 在载体 executor 接入，
         *       最终取消、半关闭与 Close/Drain 由 protocol/root owner 执行。
         */
        [[nodiscard]] auto RegisterConfiguredProvider(
            std::string Id, ProviderCandidateInputs Inputs) -> bool
        {
            return RegisterConfigured(std::move(Id),
                [Inputs = std::move(Inputs)](const auto &Candidate)
                    -> std::optional<CandidateBinding>
                { return CandidateFactory::MakeConfiguredProvider(detail::OptionsFrom(Candidate), Inputs); });
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
         * @brief 按 cold 配置候选创建 owning binding。
         * @param Candidate 同步借用的候选值；registry 不保存其地址。
         * @return builder 存在且构造成功时返回 binding，否则返回空值；异常沿调用者传播。
         * @note 仅执行同步配置/owner 组装，无网络 I/O、cancellation、executor、stream
         *       half-close 或最终关闭；成功后的 Accept/root/stream owner 负责 Close/Drain。
         */
        [[nodiscard]] auto Build(const CandidateDefinition &Candidate) const
            -> std::optional<CandidateBinding>
        {
            return BuildFrom(Candidate, State_);
        }

        /**
         * @brief 创建独立的配置候选工厂快照
         * @return 按值持有当前 builder 快照的工厂
         * @details 返回的工厂不借用当前 Registry，适合捕获到长期存活的
         *          listener/session factory 中。
         */
        [[nodiscard]] auto MakeFactory() const -> CandidateBuilder
        {
            const auto Snapshot = std::make_shared<const BuilderState>(State_);
            return [Snapshot = std::move(Snapshot)](const CandidateDefinition &Candidate)
                       -> std::optional<CandidateBinding>
            {
                return BuildFrom(Candidate, *Snapshot);
            };
        }

    private:
        [[nodiscard]] static auto BuildFrom(
            const CandidateDefinition &Candidate,
            const BuilderState &State)
            -> std::optional<CandidateBinding>
        {
            auto Protocol = std::string{};
            if (Candidate.ProtocolId.empty())
            {
                Protocol = Canonicalize(Candidate.Protocol);
            }
            else
            {
                Protocol = "instance/" + Candidate.ProtocolId;
            }
            const auto BuilderIt = State.Builders.find(Protocol);
            if (BuilderIt == State.Builders.end())
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
            const auto CanonicalScheme = detail::CanonicalCarrierScheme(Scheme);
            const auto Carrier = detail::CarrierForScheme(CanonicalScheme);
            if (!Carrier)
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
            const auto Descriptor =
                Prism::Composition::Protocol::ProtocolCatalog::Find(CanonicalScheme);
            if (!Descriptor ||
                Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Carrier)
            {
                return std::nullopt;
            }
            const CarrierRegistration *Registration = nullptr;
            if (!Candidate.CarrierId.empty())
            {
                const auto CarrierIt = State.CarriersById.find(Normalize(Candidate.CarrierId));
                if (CarrierIt == State.CarriersById.end())
                {
                    return std::nullopt;
                }
                Registration = &CarrierIt->second;
            }
            else
            {
                const auto CarrierIt = State.Carriers.find(CanonicalScheme);
                if (CarrierIt == State.Carriers.end())
                {
                    return std::nullopt;
                }
                Registration = &CarrierIt->second;
            }
            if (!Registration || (!Registration->Accept && !Registration->AcceptPrepared))
            {
                return std::nullopt;
            }
            if (Registration->Key != Descriptor->Slot())
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
            Options.Carrier = *Carrier;
            Options.HasNativeTlsContext = Registration->HasNativeTlsContext;
            if (Registration->AcceptPrepared)
            {
                return LayeredCandidateFactory::MakePrepared(
                    std::move(Options), Registration->AcceptPrepared, std::move(*Inner));
            }
            return LayeredCandidateFactory::Make(
                std::move(Options), Registration->Accept, std::move(*Inner));
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
            return Normalize(Protocol);
        }

        [[nodiscard]] auto Find(std::string_view Protocol) const
            -> const CandidateBuilder *
        {
            const auto Name = Canonicalize(Protocol);
            const auto It = State_.Builders.find(Name);
            if (It == State_.Builders.end())
            {
                return nullptr;
            }
            return &It->second;
        }

        BuilderState State_;
    };

} // namespace Prism::Composition::Recognition
