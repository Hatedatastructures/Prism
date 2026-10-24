/** @file TlsCarrierProvider.cpp @brief typed TLS carrier Prepare/Freeze/Bind 实现。 */

#include <Prism/Composition/Provider/TlsCarrierProvider.hpp>
#include <Prism/Composition/Detail/TlsCarrierMaterialBinding.hpp>

#include <Prism/Protocols/Reality/CarrierPreparation.hpp>

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Composition::Provider
{

    FrozenTlsCarrierCatalog::FrozenTlsCarrierCatalog(
        FrozenTlsCarrierCatalog&& Other) noexcept
        : Entries_(std::move(Other.Entries_)), UseState_(std::move(Other.UseState_)),
          Bound_(std::exchange(Other.Bound_, true))
    {
    }

    FrozenTlsCarrierCatalog::FrozenTlsCarrierCatalog(
        std::vector<PreparedTlsCarrier> Values,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : Entries_(std::move(Values)), UseState_(std::move(UseState))
    {
    }

    PreparedTlsCarrierCatalog::PreparedTlsCarrierCatalog(
        PreparedTlsCarrierCatalog&& Other) noexcept
        : Entries_(std::move(Other.Entries_)), UseState_(std::move(Other.UseState_)),
          Frozen_(std::exchange(Other.Frozen_, true))
    {
    }

    PreparedTlsCarrierCatalog::PreparedTlsCarrierCatalog(
        std::vector<PreparedTlsCarrier> Values,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : Entries_(std::move(Values)), UseState_(std::move(UseState))
    {
    }

    auto FrozenTlsCarrierCatalog::Bind(const std::stop_token Stop)
        -> std::expected<std::shared_ptr<BoundTlsCarrierCatalog>,
            Prism::Contract::ProviderFailure>
    {
        if (Bound_)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::AlreadyBound,
                {}, "Carriers.Bind"));
        }
        if (!Entries_.empty() && !UseState_)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::GenerationMismatch,
                {}, "Carriers.GenerationUseState"));
        }
        Bound_ = true;
        std::vector<BoundTlsCarrierCatalog::Entry> Result;
        Result.reserve(Entries_.size());
        for (auto& Value : Entries_)
        {
            if (Stop.stop_requested())
            {
                return std::unexpected(Failure(Prism::Contract::ProviderError::Cancelled,
                    Value.Id, "Carriers.Bind"));
            }
            auto Registration = BindMaterial(std::move(Value.Material), Value.Id);
            if (!Registration)
            {
                return std::unexpected(Registration.error());
            }
            Result.push_back(BoundTlsCarrierCatalog::Entry{
                Value.Key, std::move(Value.Id), std::move(*Registration)});
        }
        Entries_.clear();
        if (Stop.stop_requested())
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::Cancelled,
                {}, "Carriers.Publish"));
        }
        return std::shared_ptr<BoundTlsCarrierCatalog>(
            new BoundTlsCarrierCatalog(std::move(Result), std::move(UseState_)));
    }

    auto FrozenTlsCarrierCatalog::BindMaterial(TlsCarrierMaterial Material, const std::string& Id)
        -> std::expected<Recognition::CandidateRegistry::CarrierRegistration,
            Prism::Contract::ProviderFailure>
    {
        return std::visit([&Id](auto&& Value)
        {
            return BindMaterialValue(std::forward<decltype(Value)>(Value), Id);
        }, std::move(Material));
    }

    auto FrozenTlsCarrierCatalog::Failure(Prism::Contract::ProviderError Code,
        const std::string_view Id, const std::string_view Path)
        -> Prism::Contract::ProviderFailure
    {
        return {Code, std::string(Id), std::string(Path)};
    }

    auto PreparedTlsCarrierCatalog::Freeze()
        -> std::expected<FrozenTlsCarrierCatalog, Prism::Contract::ProviderFailure>
    {
        if (Frozen_)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::AlreadyFrozen,
                {}, "Carriers.Freeze"));
        }
        Frozen_ = true;
        return FrozenTlsCarrierCatalog(std::move(Entries_), std::move(UseState_));
    }

    auto PreparedTlsCarrierCatalog::Failure(Prism::Contract::ProviderError Code,
        const std::string_view Id, const std::string_view Path)
        -> Prism::Contract::ProviderFailure
    {
        return {Code, std::string(Id), std::string(Path)};
    }

    auto TlsCarrierProviderCatalog::Prepare(
        std::vector<Prism::Contract::CarrierConfiguration> Carriers,
        TlsCarrierPreparationServices Services)
        -> std::expected<PreparedTlsCarrierCatalog, Prism::Contract::ProviderFailure>
    {
        std::vector<PreparedTlsCarrier> Values;
        if (Services.NativeTls)
        {
            Values.push_back(PreparedTlsCarrier{
                {Protocol::ProviderCategory::TlsCarrier, Protocol::CarrierKind::Native},
                {}, NativeTlsCarrierMaterial{Services.NativeTls}});
        }
        for (const auto& Carrier : Carriers)
        {
            const auto Descriptor = Protocol::ProtocolCatalog::Find(Carrier.Builtin);
            if (!Descriptor || Descriptor->Kind != Protocol::DescriptorKind::Carrier)
            {
                return std::unexpected(Failure(Prism::Contract::ProviderError::UnsupportedInstance,
                    Carrier.Id, "Carriers.Builtin"));
            }
            auto Material = PrepareMaterial(Carrier, Descriptor->Carrier, Services);
            if (!Material)
            {
                return std::unexpected(Material.error());
            }
            Values.push_back(PreparedTlsCarrier{
                Descriptor->Slot(), Carrier.Id, std::move(*Material)});
        }
        return PreparedTlsCarrierCatalog(std::move(Values), std::move(Services.UseState));
    }

    auto TlsCarrierProviderCatalog::PrepareMaterial(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const Protocol::CarrierKind Kind,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        switch (Kind)
        {
        case Protocol::CarrierKind::Native:
            return PrepareNative(Carrier, Services);
        case Protocol::CarrierKind::Reality:
            return PrepareReality(Carrier, Services);
        case Protocol::CarrierKind::Shadowtls:
            return PrepareShadowtls(Carrier, Services);
        case Protocol::CarrierKind::Restls:
            return PrepareRestls(Carrier, Services);
        case Protocol::CarrierKind::WebSocket:
            return PrepareWebSocket(Carrier, Services);
        case Protocol::CarrierKind::Xhttp:
            return PrepareXhttp(Carrier, Services);
        case Protocol::CarrierKind::Gun:
            return PrepareGun(Carrier, Services);
        default:
            return std::unexpected(Failure(Prism::Contract::ProviderError::UnsupportedInstance,
                Carrier.Id, "Carriers.Builtin"));
        }
    }

    auto TlsCarrierProviderCatalog::PrepareNative(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        if (!std::holds_alternative<Prism::Contract::NativeTlsOptions>(Carrier.Options))
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::InvalidConfiguration,
                Carrier.Id, "Carriers.Options"));
        }
        if (!Services.NativeTls)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::MissingTls,
                Carrier.Id, "Carriers.NativeTls"));
        }
        return NativeTlsCarrierMaterial{Services.NativeTls};
    }

    auto TlsCarrierProviderCatalog::PrepareReality(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        const auto* Options = std::get_if<Prism::Contract::RealityOptions>(&Carrier.Options);
        if (!Options || !Services.ResolveSecret)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::InvalidConfiguration,
                Carrier.Id, "Carriers.Reality.Options"));
        }
        const auto Secret = Services.ResolveSecret(Options->PrivateKeyRef);
        if (!Secret)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::MissingAuthentication,
                Carrier.Id, "Carriers.Reality.PrivateKeyRef"));
        }
        auto Config = Prism::Reality::PrepareCarrier(
            Prism::Reality::CarrierPreparationRequest{
                *Secret, Options->ShortIds, Options->ServerNames});
        if (!Config)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::InvalidCredential,
                Carrier.Id, "Carriers.Reality.KeyMaterial"));
        }
        return RealityCarrierMaterial{std::move(*Config)};
    }

    auto TlsCarrierProviderCatalog::PrepareShadowtls(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        const auto* Options = std::get_if<Prism::Contract::ShadowTlsOptions>(&Carrier.Options);
        if (!Options || !Services.Dial || !Services.ResolveSecret)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::MissingResolver,
                Carrier.Id, "Carriers.ShadowTLS.Services"));
        }
        const auto Secret = Services.ResolveSecret(Options->PasswordSecretRef);
        if (!Secret || Secret->empty() || Options->Version != 3U || !Options->StrictMode ||
            Options->HandshakeTimeoutMs != 5000U)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::InvalidConfiguration,
                Carrier.Id, "Carriers.ShadowTLS.Options"));
        }
        Recognition::ShadowtlsCarrierOptions Value;
        Value.HandshakeDest = Options->HandshakeDest;
        Value.Password = *Secret;
        Value.Dial = Services.Dial;
        return ShadowtlsCarrierMaterial{std::move(Value)};
    }

    auto TlsCarrierProviderCatalog::PrepareRestls(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        const auto* Options = std::get_if<Prism::Contract::RestlsOptions>(&Carrier.Options);
        if (!Options || !Services.Dial || !Services.ResolveSecret)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::MissingResolver,
                Carrier.Id, "Carriers.Restls.Services"));
        }
        const auto Secret = Services.ResolveSecret(Options->PasswordSecretRef);
        if (!Secret || Secret->empty() || Options->HandshakeTimeoutMs != 5000U)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::InvalidConfiguration,
                Carrier.Id, "Carriers.Restls.Options"));
        }
        Recognition::RestlsCarrierOptions Value;
        Value.Host = Options->Host;
        Value.Password = *Secret;
        Value.RestlsScript = Options->RestlsScript;
        Value.Tls13 = Options->VersionHint == "tls13";
        Value.Dial = Services.Dial;
        return RestlsCarrierMaterial{std::move(Value)};
    }

    auto TlsCarrierProviderCatalog::PrepareWebSocket(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        const auto* Options = std::get_if<Prism::Contract::WebSocketOptions>(&Carrier.Options);
        if (!Options)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::InvalidConfiguration,
                Carrier.Id, "Carriers.WebSocket.Options"));
        }
        if (!Services.NativeTls)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::MissingTls,
                Carrier.Id, "Carriers.WebSocket.NativeTls"));
        }
        Prism::Ws::ServerOptions Config;
        Config.Path = Options->Path;
        Config.Host = Options->Host;
        return WebSocketCarrierMaterial{Services.NativeTls, std::move(Config)};
    }

    auto TlsCarrierProviderCatalog::PrepareXhttp(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        const auto* Options = std::get_if<Prism::Contract::XhttpOptions>(&Carrier.Options);
        if (!Options || !Services.NativeTls)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::MissingTls,
                Carrier.Id, "Carriers.Xhttp.NativeTls"));
        }
        Prism::Xhttp::Config Config;
        Config.Path = Options->Path;
        Config.Host = Options->Host;
        Config.Mode = Options->Mode;
        return XhttpCarrierMaterial{Services.NativeTls, std::move(Config)};
    }

    auto TlsCarrierProviderCatalog::PrepareGun(
        const Prism::Contract::CarrierConfiguration& Carrier,
        const TlsCarrierPreparationServices& Services)
        -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>
    {
        const auto* Options = std::get_if<Prism::Contract::GunOptions>(&Carrier.Options);
        if (!Options || !Services.NativeTls)
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::MissingTls,
                Carrier.Id, "Carriers.Gun.NativeTls"));
        }
        auto Mode = Recognition::GunServerMode::GunLite;
        if (Options->Mode == "Grpc")
        {
            Mode = Recognition::GunServerMode::Grpc;
        }
        else if (Options->Mode != "GunLite")
        {
            return std::unexpected(Failure(Prism::Contract::ProviderError::InvalidConfiguration,
                Carrier.Id, "Carriers.Gun.Mode"));
        }
        Recognition::GunServerAcceptOptions Value{
            Services.NativeTls,
            Prism::Gun::Config{Options->Path, Options->ServiceName},
            Mode};
        return GunCarrierMaterial{std::move(Value)};
    }

    auto TlsCarrierProviderCatalog::Failure(Prism::Contract::ProviderError Code,
        const std::string_view Id, const std::string_view Path)
        -> Prism::Contract::ProviderFailure
    {
        return {Code, std::string(Id), std::string(Path)};
    }

} // namespace Prism::Composition::Provider
