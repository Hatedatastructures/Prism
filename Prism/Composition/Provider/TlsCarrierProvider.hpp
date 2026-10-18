/** @file TlsCarrierProvider.hpp @brief TCP TLS carrier 的 typed Prepare/Freeze/Bind。 */
#pragma once

#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Recognition/CandidateRegistry.hpp>
#include <Prism/Composition/Recognition/RestlsCarrier.hpp>
#include <Prism/Composition/Recognition/ShadowtlsCarrier.hpp>
#include <Prism/Composition/Recognition/TlsCarrierHelpers.hpp>
#include <Prism/Composition/Provider/TlsCarrierCatalogOwner.hpp>
#include <Prism/Contract/Ingress/CarrierConfiguration.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Protocols/Reality/CarrierPreparation.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>

#include <boost/asio/ssl/context.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Composition::Provider
{
    namespace Recognition = Prism::Composition::Recognition;
    namespace Protocol = Prism::Composition::Protocol;

    /** @brief 仅在 Prepare 调用期间借用的 secret/TLS/dial 服务。 */
    struct TlsCarrierPreparationServices final
    {
        using SecretResolver = std::function<std::optional<std::string>(std::string_view)>;
        std::shared_ptr<boost::asio::ssl::context> NativeTls;
        Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
        SecretResolver ResolveSecret;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
    };

    struct NativeTlsCarrierMaterial final
    {
        std::shared_ptr<boost::asio::ssl::context> Context;
    };

    struct RealityCarrierMaterial final
    {
        Prism::Reality::PreparedConfig Config;
    };

    struct ShadowtlsCarrierMaterial final
    {
        Recognition::ShadowtlsCarrierOptions Options;
    };

    struct RestlsCarrierMaterial final
    {
        Recognition::RestlsCarrierOptions Options;
    };

    struct WebSocketCarrierMaterial final
    {
        std::shared_ptr<boost::asio::ssl::context> Context;
        Prism::Ws::ServerOptions Config;
    };

    struct XhttpCarrierMaterial final
    {
        std::shared_ptr<boost::asio::ssl::context> Context;
        Prism::Xhttp::Config Config;
    };

    struct GunCarrierMaterial final
    {
        Recognition::GunServerAcceptOptions Options;
    };

    using TlsCarrierMaterial = std::variant<NativeTlsCarrierMaterial, RealityCarrierMaterial,
        ShadowtlsCarrierMaterial, RestlsCarrierMaterial, WebSocketCarrierMaterial,
        XhttpCarrierMaterial, GunCarrierMaterial>;

    /** @brief 一个已验证、不可变的 carrier 凭据和服务材料。 */
    struct PreparedTlsCarrier final
    {
        Protocol::ProviderKey Key;
        std::string Id;
        TlsCarrierMaterial Material;
    };

    class FrozenTlsCarrierCatalog final
    {
    public:
        FrozenTlsCarrierCatalog(FrozenTlsCarrierCatalog&& Other) noexcept
            : Entries_(std::move(Other.Entries_)), UseState_(std::move(Other.UseState_)),
              Bound_(std::exchange(Other.Bound_, true))
        {
        }

        FrozenTlsCarrierCatalog(const FrozenTlsCarrierCatalog&) = delete;
        auto operator=(const FrozenTlsCarrierCatalog&) -> FrozenTlsCarrierCatalog& = delete;

        /** @brief 单次消费 prepared carrier，为每个槽位创建其 owning accept callback。 */
        [[nodiscard]] auto Bind(std::stop_token Stop)
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

    private:
        friend class PreparedTlsCarrierCatalog;

        explicit FrozenTlsCarrierCatalog(std::vector<PreparedTlsCarrier> Values,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
            : Entries_(std::move(Values)), UseState_(std::move(UseState))
        {
        }

        template<typename T>
        [[nodiscard]] static auto BindMaterialValue(T&& Value, const std::string& Id)
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

        [[nodiscard]] static auto BindMaterial(TlsCarrierMaterial Material, const std::string& Id)
            -> std::expected<Recognition::CandidateRegistry::CarrierRegistration,
                Prism::Contract::ProviderFailure>
        {
            return std::visit([&Id](auto&& Value)
            { return BindMaterialValue(std::forward<decltype(Value)>(Value), Id); }, std::move(Material));
        }

        static auto Failure(Prism::Contract::ProviderError Code,
            const std::string_view Id, const std::string_view Path)
            -> Prism::Contract::ProviderFailure
        {
            return {Code, std::string(Id), std::string(Path)};
        }

        std::vector<PreparedTlsCarrier> Entries_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        bool Bound_{false};
    };

    class PreparedTlsCarrierCatalog final
    {
    public:
        PreparedTlsCarrierCatalog(PreparedTlsCarrierCatalog&& Other) noexcept
            : Entries_(std::move(Other.Entries_)), UseState_(std::move(Other.UseState_)),
              Frozen_(std::exchange(Other.Frozen_, true))
        {
        }

        PreparedTlsCarrierCatalog(const PreparedTlsCarrierCatalog&) = delete;
        auto operator=(const PreparedTlsCarrierCatalog&) -> PreparedTlsCarrierCatalog& = delete;

        /** @brief 冻结唯一 prepared carrier 集合；不会复制 key、secret 或 service owner。 */
        [[nodiscard]] auto Freeze()
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

    private:
        friend class TlsCarrierProviderCatalog;

        explicit PreparedTlsCarrierCatalog(std::vector<PreparedTlsCarrier> Values,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
            : Entries_(std::move(Values)), UseState_(std::move(UseState))
        {
        }

        static auto Failure(Prism::Contract::ProviderError Code,
            const std::string_view Id, const std::string_view Path)
            -> Prism::Contract::ProviderFailure
        {
            return {Code, std::string(Id), std::string(Path)};
        }

        std::vector<PreparedTlsCarrier> Entries_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        bool Frozen_{false};
    };

    class TlsCarrierProviderCatalog final
    {
    public:
        /** @brief 按 typed descriptor 和协议 owner 准备所有 TCP TLS carrier。 */
        [[nodiscard]] static auto Prepare(
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

    private:
        [[nodiscard]] static auto PrepareMaterial(
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

        [[nodiscard]] static auto PrepareNative(
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

        [[nodiscard]] static auto PrepareReality(
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

        [[nodiscard]] static auto PrepareShadowtls(
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

        [[nodiscard]] static auto PrepareRestls(
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

        [[nodiscard]] static auto PrepareWebSocket(
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

        [[nodiscard]] static auto PrepareXhttp(
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

        [[nodiscard]] static auto PrepareGun(
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

        static auto Failure(Prism::Contract::ProviderError Code,
            const std::string_view Id, const std::string_view Path)
            -> Prism::Contract::ProviderFailure
        {
            return {Code, std::string(Id), std::string(Path)};
        }
    };
}
