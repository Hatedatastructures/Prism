/**
 * @file TlsCandidateFactory.hpp
 * @brief TLS carrier Runtime 候选工厂。
 * @details ClientHello 选择、carrier 接入回调和候选数据模型分别位于
 *          TlsRecognitionHelpers.hpp、TlsCarrierHelpers.hpp 与
 *          TlsCandidateModel.hpp；本头只装配最终 CandidateSpec。
 */

#pragma once

#include <utility>

#include <Preview/Composition/Recognition/TlsCandidateModel.hpp>
#include <Preview/Composition/Recognition/TlsCarrierHelpers.hpp>
#include <Preview/Composition/Recognition/TlsRecognitionHelpers.hpp>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    namespace detail
    {

        struct TlsCandidateInspector final
        {
            std::shared_ptr<const TlsMatchPolicy> Policy;

            [[nodiscard]] auto operator()(const Core::ProbeSnapshot &Snapshot) const
                -> Core::MatchState
            {
                Core::ClientHelloFeatures Features;
                const auto Parsed = ParseFeatures(Snapshot, Features);
                return Parsed == Core::MatchState::Structural
                           ? InspectFeatures(Features, *Policy)
                           : Parsed;
            }
        };

        struct TlsCandidateCommitter final
        {
            CarrierAcceptFn Accept;
            CarrierAcceptPreparedFn AcceptPrepared;
            std::string Scheme;

            [[nodiscard]] auto operator()(Core::CommitContext Context) const
                -> Net::awaitable<Core::CommitResult>
            {
                return CommitScheme(CommitSchemeRequest{
                    std::move(Context), Accept, AcceptPrepared, Scheme});
            }
        };

    } // namespace detail

    /**
     * @class TlsCandidateFactory
     * @brief 构造 TLS carrier Runtime 候选。
     */
    class TlsCandidateFactory
    {
    public:
        /**
         * @brief 构造使用普通 carrier 接入回调的 TLS 候选。
         * @param Options TLS 识别规则；候选按值拥有其中的字符串。
         * @param Accept winner 提交后执行的 carrier 接入回调；回调状态由 binding 拥有。
         * @return 可提交到 Profile 的 TLS carrier binding。
         * @details commit 没有取消点或半关闭动作；运行期取消、transport 关闭和
         *          executor 由传入的 typed callback 及其协议 owner 负责。
         */
        [[nodiscard]] static auto Make(TlsCandidateOptions Options,
                                       CarrierAcceptFn Accept)
            -> TlsCandidateBinding
        {
            return MakeBinding(std::move(Options), std::move(Accept), {});
        }

        /**
         * @brief 构造需要 prepared ClientHello 的 TLS 候选。
         * @param Options TLS 识别规则；候选按值拥有其中的字符串。
         * @param Accept prepared state 接入回调；回调状态由 binding 拥有。
         * @return 可提交到 Profile 的 TLS carrier binding。
         * @details prepared state 与 Inbound 在 commit frame 中按值传递；失败时保留
         *          原始 Inbound，最终关闭仍由 carrier/protocol owner 执行。
         */
        [[nodiscard]] static auto MakePrepared(
            TlsCandidateOptions Options,
            CarrierAcceptPreparedFn Accept) -> TlsCandidateBinding
        {
            return MakeBinding(std::move(Options), {}, std::move(Accept));
        }

    private:
        [[nodiscard]] static auto MakeBinding(
            TlsCandidateOptions Options,
            CarrierAcceptFn Accept,
            CarrierAcceptPreparedFn AcceptPrepared) -> TlsCandidateBinding
        {
            const auto DefaultScheme = detail::SchemeName(Options.Carrier);
            if (Options.Scheme.empty())
            {
                Options.Scheme = std::string(DefaultScheme);
            }
            else
            {
                Options.Scheme = detail::Normalize(Options.Scheme);
            }
            if (Options.Name.empty())
            {
                Options.Name = Options.Scheme;
            }
            // 冷配置已经校验 fallback 选择；同一值必须同时用于候选索引与 TLS inspector。
            const auto Fallback = Options.Fallback;
            // HasEch 不区分 GREASE 与真实 offer；该位不宣称 keys 已安装或 ECH 已接受。
            const auto PassesEchExtension = Options.HasNativeTlsContext ||
                Options.Carrier == TlsCarrier::Reality || Options.Carrier == TlsCarrier::Restls ||
                Options.Carrier == TlsCarrier::Shadowtls;
            Core::CandidateSpec Spec;
            Spec.Id = Options.Id;
            if (Spec.Id == Core::InvalidCandidate)
            {
                Spec.Id = 0;
            }
            Spec.Name = Options.Name;
            Spec.Scheme = Options.Scheme;
            Spec.Protocol = Preview::Contract::ProtocolType::Tls;
            Spec.Kind = Core::CandidateKind::TlsCarrier;
            Spec.Fallback = Fallback;
            Spec.MinimumBytes = Preview::Recognition::TlsRecordHeaderSize;
            TlsCandidateBinding Binding;
            Binding.Scheme = Options.Scheme;
            Binding.MatchPolicy_ = std::make_shared<const TlsMatchPolicy>(
                TlsMatchPolicy{Options.ServerNames, Options.Alpn, Fallback,
                               PassesEchExtension, Options.HasNativeTlsContext});
            const auto MatchPolicy = Binding.MatchPolicy_;
            Spec.Inspect = detail::TlsCandidateInspector{MatchPolicy};
            Spec.Prepare = detail::PrepareClientHello;
            Spec.Commit = detail::TlsCandidateCommitter{
                std::move(Accept), std::move(AcceptPrepared), Options.Scheme};
            Binding.Spec = std::move(Spec);
            return Binding;
        }
    };

} // namespace Preview::Composition::Recognition
