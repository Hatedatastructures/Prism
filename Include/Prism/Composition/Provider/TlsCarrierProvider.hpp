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
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Reality/Prepared.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <Prism/Protocols/Xhttp/ConnectionTypes.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>

#include <boost/asio/ssl/context.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
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
        FrozenTlsCarrierCatalog(FrozenTlsCarrierCatalog&& Other) noexcept;

        FrozenTlsCarrierCatalog(const FrozenTlsCarrierCatalog&) = delete;
        auto operator=(const FrozenTlsCarrierCatalog&) -> FrozenTlsCarrierCatalog& = delete;

        /** @brief 单次消费 prepared carrier，为每个槽位创建其 owning accept callback。 */
        [[nodiscard]] auto Bind(std::stop_token Stop)
            -> std::expected<std::shared_ptr<BoundTlsCarrierCatalog>,
                Prism::Contract::ProviderFailure>;

    private:
        friend class PreparedTlsCarrierCatalog;

        explicit FrozenTlsCarrierCatalog(std::vector<PreparedTlsCarrier> Values,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);

        template<typename T>
        [[nodiscard]] static auto BindMaterialValue(T&& Value, const std::string& Id)
            -> std::expected<Recognition::CandidateRegistry::CarrierRegistration,
                Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto BindMaterial(TlsCarrierMaterial Material, const std::string& Id)
            -> std::expected<Recognition::CandidateRegistry::CarrierRegistration,
                Prism::Contract::ProviderFailure>;

        static auto Failure(Prism::Contract::ProviderError Code,
            const std::string_view Id, const std::string_view Path)
            -> Prism::Contract::ProviderFailure;

        std::vector<PreparedTlsCarrier> Entries_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        bool Bound_{false};
    };

    class PreparedTlsCarrierCatalog final
    {
    public:
        PreparedTlsCarrierCatalog(PreparedTlsCarrierCatalog&& Other) noexcept;

        PreparedTlsCarrierCatalog(const PreparedTlsCarrierCatalog&) = delete;
        auto operator=(const PreparedTlsCarrierCatalog&) -> PreparedTlsCarrierCatalog& = delete;

        /** @brief 冻结唯一 prepared carrier 集合；不会复制 key、secret 或 service owner。 */
        [[nodiscard]] auto Freeze()
            -> std::expected<FrozenTlsCarrierCatalog, Prism::Contract::ProviderFailure>;

    private:
        friend class TlsCarrierProviderCatalog;

        explicit PreparedTlsCarrierCatalog(std::vector<PreparedTlsCarrier> Values,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);

        static auto Failure(Prism::Contract::ProviderError Code,
            const std::string_view Id, const std::string_view Path)
            -> Prism::Contract::ProviderFailure;

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
            -> std::expected<PreparedTlsCarrierCatalog, Prism::Contract::ProviderFailure>;

    private:
        [[nodiscard]] static auto PrepareMaterial(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const Protocol::CarrierKind Kind,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto PrepareNative(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto PrepareReality(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto PrepareShadowtls(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto PrepareRestls(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto PrepareWebSocket(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto PrepareXhttp(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        [[nodiscard]] static auto PrepareGun(
            const Prism::Contract::CarrierConfiguration& Carrier,
            const TlsCarrierPreparationServices& Services)
            -> std::expected<TlsCarrierMaterial, Prism::Contract::ProviderFailure>;

        static auto Failure(Prism::Contract::ProviderError Code,
            const std::string_view Id, const std::string_view Path)
            -> Prism::Contract::ProviderFailure;
    };
}
