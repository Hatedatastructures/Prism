/** @file TlsCarrierMaterialBinding.hpp @brief typed TLS carrier material 到 registration 的私有绑定实现。 */
#pragma once

#include <Prism/Composition/Provider/TlsCarrierProvider.hpp>

#include <type_traits>

namespace Prism::Composition::Provider
{
    template<typename T>
    auto FrozenTlsCarrierCatalog::BindMaterialValue(T&& Value, const std::string& Id)
        -> std::expected<Recognition::CandidateRegistry::CarrierRegistration,
            Prism::Contract::ProviderFailure>
    {
        using Registration = Recognition::CandidateRegistry::CarrierRegistration;
        using ValueType = std::decay_t<T>;
        if constexpr (std::is_same_v<ValueType, NativeTlsCarrierMaterial>)
        {
            const bool HasNativeTlsContext = static_cast<bool>(Value.Context);
            return Registration{{}, Recognition::MakeNativeTlsServerAccept(
                std::move(Value.Context)), {}, HasNativeTlsContext};
        }
        else if constexpr (std::is_same_v<ValueType, RealityCarrierMaterial>)
        {
            return Registration{{}, {}, Recognition::MakeRealityServerAccept(
                std::move(Value.Config))};
        }
        else if constexpr (std::is_same_v<ValueType, ShadowtlsCarrierMaterial>)
        {
            auto Accept = Recognition::MakeConfiguredShadowtlsServerAccept(
                std::move(Value.Options));
            if (!Accept)
            {
                auto Code = Prism::Contract::ProviderError::InvalidConfiguration;
                if (Accept.error() == Recognition::ShadowtlsCarrierBuildError::MissingDial)
                {
                    Code = Prism::Contract::ProviderError::MissingResolver;
                }
                return std::unexpected(Failure(Code, Id, "Carriers.ShadowTLS"));
            }
            return Registration{{}, std::move(*Accept), {}};
        }
        else if constexpr (std::is_same_v<ValueType, RestlsCarrierMaterial>)
        {
            auto Accept = Recognition::MakeConfiguredRestlsServerAccept(
                std::move(Value.Options));
            if (!Accept)
            {
                auto Code = Prism::Contract::ProviderError::InvalidConfiguration;
                if (Accept.error() == Recognition::RestlsCarrierBuildError::MissingDial)
                {
                    Code = Prism::Contract::ProviderError::MissingResolver;
                }
                return std::unexpected(Failure(Code, Id, "Carriers.Restls"));
            }
            return Registration{{}, std::move(*Accept), {}};
        }
        else if constexpr (std::is_same_v<ValueType, WebSocketCarrierMaterial>)
        {
            const bool HasNativeTlsContext = static_cast<bool>(Value.Context);
            return Registration{{}, Recognition::MakeWebsocketServerAccept(
                std::move(Value.Context), std::move(Value.Config)), {}, HasNativeTlsContext};
        }
        else if constexpr (std::is_same_v<ValueType, XhttpCarrierMaterial>)
        {
            const bool HasNativeTlsContext = static_cast<bool>(Value.Context);
            return Registration{{}, Recognition::MakeXhttpServerAccept(
                std::move(Value.Context), std::move(Value.Config)), {}, HasNativeTlsContext};
        }
        else
        {
            const bool HasNativeTlsContext = static_cast<bool>(Value.Options.TlsContext);
            return Registration{{}, Recognition::MakeGunServerAccept(
                std::move(Value.Options)), {}, HasNativeTlsContext};
        }
    }
}
