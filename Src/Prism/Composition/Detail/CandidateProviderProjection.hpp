/** @file CandidateProviderProjection.hpp @brief provider owner 到 recognition binding 的私有投影。 */
#pragma once

#include <Prism/Composition/Recognition/CandidateFactory.hpp>

#include <type_traits>

namespace Prism::Composition::Recognition
{
    template<typename T>
    auto CandidateFactory::ProjectProvider(CandidateOptions Options, const T &Owner,
        const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
        -> std::optional<CandidateBinding>
    {
        using Binding = std::remove_const_t<typename std::decay_t<T>::element_type>;
        if (!Owner) return std::nullopt;
        std::shared_ptr<Prism::Mux::RootBinding> MuxRoot;
        if (Mux)
        {
            MuxRoot = Mux->Owner;
        }
        if constexpr (std::is_same_v<Binding, Prism::Socks5::Binding>)
        {
            auto Factory = Owner->WithAdmission(Prism::Socks5::Binding::AdmissionPolicy{
                .Mux = MuxRoot, .UdpEnabled = Options.UdpEnabled});
            if (!Factory) return std::nullopt;
            return MakeSocks5(std::move(Options), std::move(Factory));
        }
        else if constexpr (std::is_same_v<Binding, Prism::Shadowsocks2022::Binding>)
        {
            auto Factory = Owner;
            if (MuxRoot)
            {
                Factory = Owner->WithMux(MuxRoot);
            }
            if (!Factory) return std::nullopt;
            return MakeSs2022(std::move(Options), std::move(Factory));
        }
        else if constexpr (std::is_same_v<Binding, Prism::Http11::Binding>)
        {
            return MakeHttp(std::move(Options), Owner);
        }
        else if constexpr (std::is_same_v<Binding, Prism::Vless::Binding>)
        {
            return ProjectVless(std::move(Options), Owner, Mux);
        }
        else if constexpr (std::is_same_v<Binding, Prism::Trojan::Binding>)
        {
            return ProjectTrojan(std::move(Options), Owner, Mux);
        }
        else if constexpr (std::is_same_v<Binding, Prism::Vmess::Binding>)
        {
            return ProjectVmess(std::move(Options), Owner, Mux);
        }
        else if constexpr (std::is_same_v<Binding, Prism::Anytls::Binding>)
        {
            auto Projection = Owner->BeginProjection();
            if (!Projection) return std::nullopt;
            return MakeAnytls(std::move(Options), Projection->Options());
        }
        else if constexpr (std::is_same_v<Binding, Prism::Trusttunnel::Binding>)
        {
            return MakeTrusttunnelCandidate(std::move(Options), Owner->NativeTls, Owner->Wire);
        }
        else return std::nullopt;
    }
}
