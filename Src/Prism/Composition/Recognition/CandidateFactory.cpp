/** @file CandidateFactory.cpp @brief protocol candidate 与 provider ingress 投影实现。 */

#include <Prism/Composition/Recognition/CandidateFactory.hpp>

#include <Prism/Composition/Detail/CandidateProviderProjection.hpp>
#include <Prism/Composition/Recognition/CandidateFactoryHelpers.hpp>
#include <Prism/Composition/Recognition/TrusttunnelCandidate.hpp>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>

namespace Prism::Composition::Recognition
{
    namespace configured_detail
    {

        auto MuxForBinding(const std::string_view BindingId,
            const std::vector<Prism::Composition::Provider::BoundMux>& Muxes)
            -> std::optional<Prism::Composition::Provider::BoundMux>
        {
            if (BindingId.empty())
            {
                return std::nullopt;
            }
            for (const auto& Mux : Muxes)
            {
                if (Mux.Id == BindingId)
                {
                    return Mux;
                }
            }
            return std::nullopt;
        }

    } // namespace configured_detail

    auto CandidateFactory::PrepareBoundSs(
        const std::shared_ptr<Prism::Shadowsocks2022::Binding>& Binding,
        Core::PrepareContext Context) -> Core::PrepareResult
    {
        const auto Bytes = detail::SnapshotBytes(Context.Snapshot);
        const auto Status = Binding->Inspect(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(Bytes.data()), Bytes.size()));
        if (Status == Prism::Error::None) return detail::Accepted(Context.Candidate);
        if (Status == Prism::Error::NeedMore) return detail::NeedMore(Context.Candidate);
        return detail::NoMatch(Context.Candidate);
    }

    auto CandidateFactory::PrepareHttp(Core::PrepareContext Context)
        -> Net::awaitable<Core::PrepareResult>
    {
        const auto State = detail::InspectHttp(Context.Snapshot);
        if (State == Core::MatchState::NeedMore)
        {
            co_return detail::NeedMore(Context.Candidate);
        }
        if (State == Core::MatchState::Structural || State == Core::MatchState::Authenticated)
        {
            co_return detail::Accepted(Context.Candidate);
        }
        co_return detail::NoMatch(Context.Candidate);
    }

    auto CandidateFactory::MakeHttp(CandidateOptions Options,
        std::shared_ptr<Prism::Http11::Binding> Factory) -> CandidateBinding
    {
        auto Spec = detail::BaseSpec(
            std::move(Options), "http", Prism::Contract::ProtocolType::Http);
        Spec.Kind = Core::CandidateKind::Cleartext;
        Spec.MinimumBytes = 1;
        Spec.FirstBytes = {'C', 'G', 'P', 'H', 'O', 'T', 'D'};
        Spec.RequiresAuthentication = true;
        Spec.Inspect = detail::InspectHttp;
        Spec.Prepare = PrepareHttp;
        return CandidateBinding{std::move(Spec), std::move(Factory)};
    }

    auto CandidateFactory::MakeSocks5(CandidateOptions Options,
        std::shared_ptr<Prism::Socks5::Binding> Binding) -> CandidateBinding
    {
        auto Spec = detail::BaseSpec(
            std::move(Options), "socks5", Prism::Contract::ProtocolType::Socks5);
        Spec.Kind = Core::CandidateKind::Cleartext;
        Spec.MinimumBytes = 2;
        Spec.FirstBytes = {Prism::Socks5::Version};
        Spec.Inspect = detail::InspectSocks5;
        return {std::move(Spec), std::move(Binding)};
    }

    auto CandidateFactory::MakeSs2022(CandidateOptions Options,
        std::shared_ptr<Prism::Shadowsocks2022::Binding> Binding) -> CandidateBinding
    {
        auto Spec = detail::BaseSpec(
            std::move(Options), "ss2022", Prism::Contract::ProtocolType::Shadowsocks);
        Spec.Kind = Core::CandidateKind::Opaque;
        Spec.RequiresAuthentication = true;
        Spec.Fallback = true;
        Spec.MinimumBytes = 43;
        Spec.Inspect = [](const Core::ProbeSnapshot& Snapshot)
        {
            return detail::InspectOpaqueLength(Snapshot, 43);
        };
        Spec.Prepare = [Binding](Core::PrepareContext Context) -> Net::awaitable<Core::PrepareResult>
        {
            co_return PrepareBoundSs(Binding, std::move(Context));
        };
        return {std::move(Spec), std::move(Binding)};
    }

    auto CandidateFactory::MakeAnytls(CandidateOptions Options,
        Prism::Anytls::IngressOptions Config) -> CandidateBinding
    {
        const auto Password = Config.Configuration.Password;
        auto Spec = detail::BaseSpec(
            std::move(Options), "anytls", Prism::Contract::ProtocolType::AnyTls);
        Spec.Kind = Core::CandidateKind::Opaque;
        Spec.RequiresAuthentication = true;
        Spec.Fallback = true;
        Spec.MinimumBytes = Prism::Anytls::AuthFrameHdrlen;
        Spec.Inspect = [Password](const Core::ProbeSnapshot& Snapshot)
        {
            return detail::InspectAnytls(Snapshot, Password);
        };
        Spec.Prepare = [Password](Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>
        {
            co_return detail::PrepareAnytls(
                detail::AnytlsPrepareRequest{Context.Candidate, Password, Context.Snapshot});
        };
        auto Handler = std::make_shared<Prism::Anytls::IngressFactory>(std::move(Config));
        return CandidateBinding{std::move(Spec), std::move(Handler)};
    }

    auto CandidateFactory::ProjectVless(CandidateOptions Options,
        const std::shared_ptr<const Prism::Vless::Binding>& Owner,
        const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
        -> std::optional<CandidateBinding>
    {
        if (!Owner) return std::nullopt;
        const auto Material = Owner->Material();
        if (!Material) return std::nullopt;
        Prism::Vless::IngressRoute Route;
        Route.EnableUdp = Options.UdpEnabled;
        if (Mux) Route.Mux = Mux->Owner;
        auto Handler = Owner->WithIngress(std::move(Route));
        if (!Handler) return std::nullopt;
        const auto Uuid = Material->Configuration.uuid;
        const auto AuthenticatorOwner = Material->Configuration.AuthenticatorOwner;
        const auto UdpEnabled = Material->Configuration.EnableUdp && Options.UdpEnabled;
        auto Spec = detail::BaseSpec(std::move(Options), "vless",
            Prism::Contract::ProtocolType::Vless);
        Spec.Kind = Core::CandidateKind::Cleartext;
        Spec.RequiresAuthentication = true;
        Spec.MinimumBytes = 19;
        Spec.FirstBytes = {Prism::Vless::ProtocolVersion};
        Spec.Inspect = detail::InspectVless;
        Spec.Prepare = [Uuid, AuthenticatorOwner, UdpEnabled](Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>
        {
            co_return detail::PrepareVless(detail::VlessPrepareRequest{
                Context.Candidate, Uuid, AuthenticatorOwner, Context.Snapshot, UdpEnabled});
        };
        return CandidateBinding{std::move(Spec), std::move(Handler)};
    }

    auto CandidateFactory::ProjectTrojan(CandidateOptions Options,
        const std::shared_ptr<const Prism::Trojan::Binding>& Owner,
        const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
        -> std::optional<CandidateBinding>
    {
        if (!Owner) return std::nullopt;
        const auto Material = Owner->Material();
        if (!Material) return std::nullopt;
        Prism::Trojan::IngressRoute Route;
        if (Mux) Route.Mux = Mux->Owner;
        auto Handler = Owner->WithIngress(std::move(Route));
        if (!Handler) return std::nullopt;
        const auto EnableTcp = Material->Configuration.EnableTcp;
        const auto EnableUdp = Material->Configuration.EnableUdp && Options.UdpEnabled;
        const auto AuthenticatorOwner = Material->Configuration.AuthenticatorOwner;
        auto Spec = detail::BaseSpec(std::move(Options), "trojan",
            Prism::Contract::ProtocolType::Trojan);
        Spec.Kind = Core::CandidateKind::Opaque;
        Spec.RequiresAuthentication = true;
        Spec.Fallback = true;
        Spec.MinimumBytes = Prism::Trojan::CredentialLen + 2;
        Spec.Inspect = detail::InspectTrojan;
        Spec.Prepare = [EnableTcp, EnableUdp, AuthenticatorOwner](Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>
        {
            co_return detail::PrepareTrojan(detail::TrojanPrepareRequest{
                Context.Candidate, {}, EnableTcp, EnableUdp, AuthenticatorOwner, Context.Snapshot});
        };
        return CandidateBinding{std::move(Spec), std::move(Handler)};
    }

    auto CandidateFactory::ProjectVmess(CandidateOptions Options,
        const std::shared_ptr<const Prism::Vmess::Binding>& Owner,
        const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
        -> std::optional<CandidateBinding>
    {
        if (!Owner) return std::nullopt;
        const auto Material = Owner->Material();
        if (!Material) return std::nullopt;
        Prism::Vmess::IngressRoute Route;
        if (Mux) Route.Mux = Mux->Owner;
        auto Handler = Owner->WithIngress(std::move(Route));
        if (!Handler) return std::nullopt;
        const auto Uuid = Material->Configuration.uuid;
        const auto Credentials = Material->Credentials;
        const auto UdpEnabled = Material->Configuration.EnableUdp && Options.UdpEnabled;
        auto Spec = detail::BaseSpec(std::move(Options), "vmess",
            Prism::Contract::ProtocolType::Vmess);
        Spec.Kind = Core::CandidateKind::Opaque;
        Spec.RequiresAuthentication = true;
        Spec.Fallback = true;
        Spec.MinimumBytes = 60;
        Spec.Inspect = [](const Core::ProbeSnapshot& Snapshot)
        {
            return detail::InspectOpaqueLength(Snapshot, 60);
        };
        Spec.Prepare = [Uuid, Credentials, UdpEnabled](Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>
        {
            co_return detail::PrepareVmess(detail::VmessPrepareRequest{
                Context.Candidate, Uuid, Credentials, Context.Snapshot, UdpEnabled});
        };
        return CandidateBinding{std::move(Spec), std::move(Handler)};
    }

    auto CandidateFactory::MakeVless(CandidateOptions Options,
        std::shared_ptr<const Prism::Vless::Binding> Owner,
        std::optional<Prism::Composition::Provider::BoundMux> Mux)
        -> std::optional<CandidateBinding>
    {
        return ProjectVless(std::move(Options), Owner, Mux);
    }

    auto CandidateFactory::MakeTrojan(CandidateOptions Options,
        std::shared_ptr<const Prism::Trojan::Binding> Owner,
        std::optional<Prism::Composition::Provider::BoundMux> Mux)
        -> std::optional<CandidateBinding>
    {
        return ProjectTrojan(std::move(Options), Owner, Mux);
    }

    auto CandidateFactory::MakeVmess(CandidateOptions Options,
        std::shared_ptr<const Prism::Vmess::Binding> Owner,
        std::optional<Prism::Composition::Provider::BoundMux> Mux)
        -> std::optional<CandidateBinding>
    {
        return ProjectVmess(std::move(Options), Owner, Mux);
    }

    auto CandidateFactory::MakeConfiguredProvider(CandidateOptions Options,
        const ProviderCandidateInputs& Inputs) -> std::optional<CandidateBinding>
    {
        const auto Mux = configured_detail::MuxForBinding(Options.BindingId, Inputs.Muxes);
        const auto Project = [&Options, &Mux](const auto& Owner)
            -> std::optional<CandidateBinding>
        {
            return ProjectProvider(Options, Owner, Mux);
        };
        return std::visit(Project, Inputs.Owner.Owner);
    }

} // namespace Prism::Composition::Recognition
