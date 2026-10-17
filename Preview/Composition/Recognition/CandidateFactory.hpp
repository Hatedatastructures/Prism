/**
 * @file CandidateFactory.hpp
 * @brief Composition 层协议候选与 handler resolver 工厂
 * @details CandidateSpec 只保存 Runtime 可理解的结构检查、认证准备和
 *          replay 提交回调；具体 ProtocolHandler 由返回的 Accept 回调持有，
 *          只有 Session 在 winner 确定后才会调用它。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <Preview/Composition/Recognition/CandidateFactoryHelpers.hpp>
#include <Preview/Composition/Recognition/TrusttunnelCandidate.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <Preview/Protocols/Http1/IngressFactory.hpp>
#include <Preview/Protocols/Http1/Binding.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Protocols/Shadowsocks2022/Binding.hpp>
#include <Preview/Protocols/Socks5/Binding.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>
#include <type_traits>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    /**
     * @brief 已绑定 provider 的候选构造材料；共享唯一协议 owner，不复制认证材料。
     * @details 仅用于监听前的冷构造；Muxes 是 ProviderCatalog 已绑定的 owning roots。
     *          候选发布后，协议 binding 和 BoundCatalog 负责实际取消、排空与最终关闭。
     */
    struct ProviderCandidateInputs final
    {
        Preview::Composition::Provider::BoundInstance Owner;
        std::vector<Preview::Composition::Provider::BoundMux> Muxes;
    };

    namespace configured_detail
    {
        [[nodiscard]] inline auto MuxForBinding(
            const std::string_view BindingId,
            const std::vector<Preview::Composition::Provider::BoundMux> &Muxes)
            -> std::optional<Preview::Composition::Provider::BoundMux>
        {
            if (BindingId.empty())
            {
                return std::nullopt;
            }
            for (const auto &Mux : Muxes)
            {
                if (Mux.Id == BindingId)
                {
                    return Mux;
                }
            }
            return std::nullopt;
        }
    }

    /**
     * @class CandidateFactory
     * @brief 创建标准协议候选及 winner-only handler resolver
     */
    class CandidateFactory
    {
        /** @brief 同步将具体 provider owner、候选元数据和可选 mux root 投影为 owning binding。 */
        template<typename T>
        [[nodiscard]] static auto ProjectProvider(CandidateOptions Options, const T &Owner,
            const std::optional<Preview::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>
        {
            using Binding = std::remove_const_t<typename std::decay_t<T>::element_type>;
            if (!Owner) return std::nullopt;
            std::shared_ptr<Preview::Mux::RootBinding> MuxRoot;
            if (Mux)
            {
                MuxRoot = Mux->Owner;
            }
            if constexpr (std::is_same_v<Binding, Preview::Socks5::Binding>)
            {
                auto Factory = Owner->WithAdmission(Preview::Socks5::Binding::AdmissionPolicy{
                    .Mux = MuxRoot, .UdpEnabled = Options.UdpEnabled});
                if (!Factory) return std::nullopt;
                return MakeSocks5(std::move(Options), std::move(Factory));
            }
            else if constexpr (std::is_same_v<Binding, Preview::Shadowsocks2022::Binding>)
            {
                auto Factory = Owner;
                if (MuxRoot)
                {
                    Factory = Owner->WithMux(MuxRoot);
                }
                if (!Factory) return std::nullopt;
                return MakeSs2022(std::move(Options), std::move(Factory));
            }
            else if constexpr (std::is_same_v<Binding, Preview::Http11::Binding>)
            {
                return MakeHttp(std::move(Options), Owner);
            }
            else if constexpr (std::is_same_v<Binding, Preview::Vless::Binding>)
            {
                return ProjectVless(std::move(Options), Owner, Mux);
            }
            else if constexpr (std::is_same_v<Binding, Preview::Trojan::Binding>)
            {
                return ProjectTrojan(std::move(Options), Owner, Mux);
            }
            else if constexpr (std::is_same_v<Binding, Preview::Vmess::Binding>)
            {
                return ProjectVmess(std::move(Options), Owner, Mux);
            }
            else if constexpr (std::is_same_v<Binding, Preview::Anytls::Binding>)
            {
                auto Projection = Owner->BeginProjection();
                if (!Projection) return std::nullopt;
                return MakeAnytls(std::move(Options), Projection->Options());
            }
            else if constexpr (std::is_same_v<Binding, Preview::Trusttunnel::Binding>)
            {
                return MakeTrusttunnelCandidate(std::move(Options), Owner->NativeTls, Owner->Wire);
            }
            else return std::nullopt;
        }

        static auto PrepareBoundSs(const std::shared_ptr<Preview::Shadowsocks2022::Binding>& Binding,
            Core::PrepareContext Context)->Core::PrepareResult
        {
            const auto Bytes=detail::SnapshotBytes(Context.Snapshot);
            const auto Status=Binding->Inspect(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(Bytes.data()),Bytes.size()));
            if(Status==Preview::Error::None)return detail::Accepted(Context.Candidate);
            if(Status==Preview::Error::NeedMore)return detail::NeedMore(Context.Candidate);
            return detail::NoMatch(Context.Candidate);
        }

        static auto PrepareHttp(Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>
        {
            const auto State = detail::InspectHttp(Context.Snapshot);
            if (State == Core::MatchState::NeedMore)
            {
                co_return detail::NeedMore(Context.Candidate);
            }
            if (State == Core::MatchState::Structural ||
                State == Core::MatchState::Authenticated)
            {
                co_return detail::Accepted(Context.Candidate);
            }
            co_return detail::NoMatch(Context.Candidate);
        }

    public:
        [[nodiscard]] static auto MakeHttp(
            CandidateOptions Options,
            std::shared_ptr<Preview::Http11::Binding> Factory)
            -> CandidateBinding
        {
            auto Spec = detail::BaseSpec(std::move(Options), "http", Preview::Contract::ProtocolType::Http);
            Spec.Kind = Core::CandidateKind::Cleartext;
            Spec.MinimumBytes = 1;
            Spec.FirstBytes = {'C', 'G', 'P', 'H', 'O', 'T', 'D'};
            Spec.RequiresAuthentication = true;
            Spec.Inspect = detail::InspectHttp;
            Spec.Prepare = PrepareHttp;
            return CandidateBinding{std::move(Spec), std::move(Factory)};
        }

        /** @brief 冷路径接收真实绑定；候选仅检查 wire，winner 消费同一 factory。 */
        [[nodiscard]] static auto MakeSocks5(CandidateOptions Options,
            std::shared_ptr<Preview::Socks5::Binding> Binding) -> CandidateBinding
        {
            auto Spec=detail::BaseSpec(std::move(Options),"socks5",Preview::Contract::ProtocolType::Socks5);
            Spec.Kind=Core::CandidateKind::Cleartext;
            Spec.MinimumBytes=2; Spec.FirstBytes={Preview::Socks5::Version};
            Spec.Inspect=detail::InspectSocks5;
            return {std::move(Spec),std::move(Binding)};
        }
        /** @brief 只使用实际绑定中的多账户 key；检查不调用认证器或取得任何 lease。 */
        [[nodiscard]] static auto MakeSs2022(CandidateOptions Options,
            std::shared_ptr<Preview::Shadowsocks2022::Binding> Binding) -> CandidateBinding
        {
            auto Spec=detail::BaseSpec(std::move(Options),"ss2022",Preview::Contract::ProtocolType::Shadowsocks);
            Spec.Kind=Core::CandidateKind::Opaque; Spec.RequiresAuthentication=true;
            Spec.Fallback=true; Spec.MinimumBytes=43;
            Spec.Inspect=[](const Core::ProbeSnapshot& Snapshot){return detail::InspectOpaqueLength(Snapshot,43);};
            Spec.Prepare=[Binding](Core::PrepareContext Context)->Net::awaitable<Core::PrepareResult>
            { co_return PrepareBoundSs(Binding,std::move(Context)); };
            return {std::move(Spec),std::move(Binding)};
        }

        /** @brief 从已经冻结的 VLESS binding 构造 recognition owner。 */
        [[nodiscard]] static auto MakeVless(CandidateOptions Options,
            std::shared_ptr<const Preview::Vless::Binding> Owner,
            std::optional<Preview::Composition::Provider::BoundMux> Mux)
            -> std::optional<CandidateBinding>
        {
            return ProjectVless(std::move(Options), Owner, Mux);
        }

        /** @brief 从已经冻结的 Trojan binding 构造 recognition owner。 */
        [[nodiscard]] static auto MakeTrojan(CandidateOptions Options,
            std::shared_ptr<const Preview::Trojan::Binding> Owner,
            std::optional<Preview::Composition::Provider::BoundMux> Mux)
            -> std::optional<CandidateBinding>
        {
            return ProjectTrojan(std::move(Options), Owner, Mux);
        }

        /** @brief 从已经冻结的 VMess binding 构造 recognition owner。 */
        [[nodiscard]] static auto MakeVmess(CandidateOptions Options,
            std::shared_ptr<const Preview::Vmess::Binding> Owner,
            std::optional<Preview::Composition::Provider::BoundMux> Mux)
            -> std::optional<CandidateBinding>
        {
            return ProjectVmess(std::move(Options), Owner, Mux);
        }
        [[nodiscard]] static auto MakeAnytls(CandidateOptions Options,
                                             Preview::Anytls::IngressOptions Config = {}) -> CandidateBinding
        {
            const auto Password = Config.Configuration.Password;
            auto Spec = detail::BaseSpec(std::move(Options), "anytls", Preview::Contract::ProtocolType::AnyTls);
            Spec.Kind = Core::CandidateKind::Opaque;
            Spec.RequiresAuthentication = true;
            Spec.Fallback = true;
            Spec.MinimumBytes = Preview::Anytls::AuthFrameHdrlen;
            Spec.Inspect = [Password](const Core::ProbeSnapshot &Snapshot)
            { return detail::InspectAnytls(Snapshot, Password); };
            Spec.Prepare = [Password](Core::PrepareContext Context) -> Net::awaitable<Core::PrepareResult>
            {
                co_return detail::PrepareAnytls(
                    detail::AnytlsPrepareRequest{Context.Candidate, Password, Context.Snapshot});
            };
            auto Handler = std::make_shared<Preview::Anytls::IngressFactory>(std::move(Config));
            return CandidateBinding{std::move(Spec), std::move(Handler)};
        }

        /**
         * @brief 同步借用 typed 配置和服务，构造拥有完整 VLESS 接入状态的候选。
         * @param Options 按值接管的候选元数据；Inputs 只借用到本次同步返回。
         * @return 拥有 ingress 的 binding；分配异常直接传播，没有异步取消或半关闭。
         * @note 后续 Accept 在入站 executor 运行，协议/root owner 负责取消、半关闭和最终关闭。
         */
    private:
        /** @brief VLESS recognition 只借用同一个 Binding 的冷 UUID 和认证器。 */
        [[nodiscard]] static auto ProjectVless(CandidateOptions Options,
            const std::shared_ptr<const Preview::Vless::Binding>& Owner,
            const std::optional<Preview::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>
        {
            if (!Owner) return std::nullopt;
            const auto Material = Owner->Material();
            if (!Material) return std::nullopt;
            Preview::Vless::IngressRoute Route;
            if (Mux) Route.Mux = Mux->Owner;
            auto Handler = Owner->WithIngress(std::move(Route));
            if (!Handler) return std::nullopt;
            const auto Uuid = Material->Configuration.uuid;
            const auto AuthenticatorOwner = Material->Configuration.AuthenticatorOwner;
            auto Spec = detail::BaseSpec(std::move(Options), "vless",
                Preview::Contract::ProtocolType::Vless);
            Spec.Kind = Core::CandidateKind::Cleartext;
            Spec.RequiresAuthentication = true;
            Spec.MinimumBytes = 19;
            Spec.FirstBytes = {Preview::Vless::ProtocolVersion};
            Spec.Inspect = detail::InspectVless;
            Spec.Prepare = [Uuid, AuthenticatorOwner](Core::PrepareContext Context)
                -> Net::awaitable<Core::PrepareResult>
            {
                co_return detail::PrepareVless(detail::VlessPrepareRequest{
                    Context.Candidate, Uuid, AuthenticatorOwner, Context.Snapshot});
            };
            return CandidateBinding{std::move(Spec), std::move(Handler)};
        }

        /** @brief Trojan handler 持有原 Binding；认证轨迹不另行复制 password。 */
        [[nodiscard]] static auto ProjectTrojan(CandidateOptions Options,
            const std::shared_ptr<const Preview::Trojan::Binding>& Owner,
            const std::optional<Preview::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>
        {
            if (!Owner) return std::nullopt;
            const auto Material = Owner->Material();
            if (!Material) return std::nullopt;
            Preview::Trojan::IngressRoute Route;
            if (Mux) Route.Mux = Mux->Owner;
            auto Handler = Owner->WithIngress(std::move(Route));
            if (!Handler) return std::nullopt;
            const auto EnableTcp = Material->Configuration.EnableTcp;
            const auto EnableUdp = Material->Configuration.EnableUdp;
            const auto AuthenticatorOwner = Material->Configuration.AuthenticatorOwner;
            auto Spec = detail::BaseSpec(std::move(Options), "trojan",
                Preview::Contract::ProtocolType::Trojan);
            Spec.Kind = Core::CandidateKind::Opaque;
            Spec.RequiresAuthentication = true;
            Spec.Fallback = true;
            Spec.MinimumBytes = Preview::Trojan::CredentialLen + 2;
            Spec.Inspect = detail::InspectTrojan;
            Spec.Prepare = [EnableTcp, EnableUdp, AuthenticatorOwner](Core::PrepareContext Context)
                -> Net::awaitable<Core::PrepareResult>
            {
                co_return detail::PrepareTrojan(detail::TrojanPrepareRequest{
                    Context.Candidate, {}, EnableTcp, EnableUdp, AuthenticatorOwner,
                    Context.Snapshot});
            };
            return CandidateBinding{std::move(Spec), std::move(Handler)};
        }

        /** @brief VMess recognition 复用原 credential scope 和 session owner。 */
        [[nodiscard]] static auto ProjectVmess(CandidateOptions Options,
            const std::shared_ptr<const Preview::Vmess::Binding>& Owner,
            const std::optional<Preview::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>
        {
            if (!Owner) return std::nullopt;
            const auto Material = Owner->Material();
            if (!Material) return std::nullopt;
            Preview::Vmess::IngressRoute Route;
            if (Mux) Route.Mux = Mux->Owner;
            auto Handler = Owner->WithIngress(std::move(Route));
            if (!Handler) return std::nullopt;
            const auto Uuid = Material->Configuration.uuid;
            const auto Credentials = Material->Credentials;
            auto Spec = detail::BaseSpec(std::move(Options), "vmess",
                Preview::Contract::ProtocolType::Vmess);
            Spec.Kind = Core::CandidateKind::Opaque;
            Spec.RequiresAuthentication = true;
            Spec.Fallback = true;
            Spec.MinimumBytes = 60;
            Spec.Inspect = [](const Core::ProbeSnapshot& Snapshot)
            { return detail::InspectOpaqueLength(Snapshot, 60); };
            Spec.Prepare = [Uuid, Credentials](Core::PrepareContext Context)
                -> Net::awaitable<Core::PrepareResult>
            {
                co_return detail::PrepareVmess(detail::VmessPrepareRequest{
                    Context.Candidate, Uuid, Credentials, Context.Snapshot});
            };
            return CandidateBinding{std::move(Spec), std::move(Handler)};
        }

        /**
         * @brief 从唯一 provider material 派生候选，具体协议投影由 Composition 完成。
         * @param Options 按值接管元数据；Inputs 只在同步冷构造期间借用。
         * @return 支持的 TCP provider 返回 owning binding；空 owner 或非 TCP family 返回空值。
         * @note 不复制 secret/lease，不执行网络 I/O；分配异常直接传播。后续接入在载体
         *       executor 运行，取消、半关闭与最终 Close/Drain 由协议 binding/root owner 执行。
         */
    public:
        [[nodiscard]] static auto MakeConfiguredProvider(
            CandidateOptions Options, const ProviderCandidateInputs &Inputs)
            -> std::optional<CandidateBinding>
        {
            const auto Mux = configured_detail::MuxForBinding(Options.BindingId, Inputs.Muxes);
            const auto Project = [&Options, &Mux](const auto &Owner)
                -> std::optional<CandidateBinding>
            { return ProjectProvider(Options, Owner, Mux); };
            return std::visit(Project, Inputs.Owner.Owner);
        }

    };

} // namespace Preview::Composition::Recognition
