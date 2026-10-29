/** @file TlsCandidateFactory.cpp @brief TLS carrier Recognition binding 构造实现。 */

#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Composition/Recognition/TlsCarrierHelpers.hpp>
#include <Prism/Composition/Recognition/Detail/Helpers.hpp>

#include <memory>
#include <string>
#include <utility>

namespace Prism::Composition::Recognition
{
    namespace
    {
        struct TlsCandidateInspector final
        {
            std::shared_ptr<const TlsMatchPolicy> Policy;

            [[nodiscard]] auto operator()(const Core::ProbeSnapshot& Snapshot) const
                -> Core::MatchState
            {
                Core::ClientHelloFeatures Features;
                const auto Parsed = detail::ParseFeatures(Snapshot, Features);
                return Parsed == Core::MatchState::Structural
                    ? detail::InspectFeatures(Features, *Policy)
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
                return detail::CommitScheme(detail::CommitSchemeRequest{
                    std::move(Context), Accept, AcceptPrepared, Scheme});
            }
        };
    }

    auto TlsCandidateFactory::Make(TlsCandidateOptions Options, CarrierAcceptFn Accept)
        -> TlsCandidateBinding
    {
        return MakeBinding(std::move(Options), std::move(Accept), {});
    }

    auto TlsCandidateFactory::MakePrepared(
        TlsCandidateOptions Options, CarrierAcceptPreparedFn Accept) -> TlsCandidateBinding
    {
        return MakeBinding(std::move(Options), {}, std::move(Accept));
    }

    auto TlsCandidateFactory::MakeBinding(TlsCandidateOptions Options,
        CarrierAcceptFn Accept, CarrierAcceptPreparedFn AcceptPrepared)
        -> TlsCandidateBinding
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
        Spec.Protocol = Prism::Contract::ProtocolType::Tls;
        Spec.Kind = Core::CandidateKind::TlsCarrier;
        Spec.Fallback = Fallback;
        Spec.MinimumBytes = Prism::Recognition::TlsRecordHeaderSize;
        TlsCandidateBinding Binding;
        Binding.Scheme = Options.Scheme;
        Binding.MatchPolicy_ = std::make_shared<const TlsMatchPolicy>(
            TlsMatchPolicy{Options.ServerNames, Options.Alpn, Fallback,
                PassesEchExtension, Options.HasNativeTlsContext});
        const auto MatchPolicy = Binding.MatchPolicy_;
        Spec.Inspect = TlsCandidateInspector{MatchPolicy};
        Spec.Prepare = detail::PrepareClientHello;
        Spec.Commit = TlsCandidateCommitter{
            std::move(Accept), std::move(AcceptPrepared), Options.Scheme};
        Binding.Spec = std::move(Spec);
        return Binding;
    }

} // namespace Prism::Composition::Recognition
