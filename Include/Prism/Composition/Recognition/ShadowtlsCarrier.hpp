/**
 * @file ShadowtlsCarrier.hpp
 * @brief 配置驱动的 ShadowTLS carrier 构造。
 * @details 将配置中的 HandshakeDest/password 与 runtime DialFn 绑定到真实
 *          ShadowTLS ServerSession；不在 composition 层保存 secret 解析器或
 *          伪造 outbound transport。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace Prism::Composition::Recognition
{

    enum class ShadowtlsCarrierBuildError : std::uint8_t
    {
        MissingPassword,
        MissingDial,
        InvalidDestination,
    };

    struct ShadowtlsCarrierOptions final
    {
        std::string HandshakeDest;
        std::string Password;
        Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
    };

    namespace detail
    {

        struct ShadowtlsHostPort final
        {
            std::string Host;
            std::uint16_t Port{0};
        };

        struct ShadowtlsDialTarget final
        {
            Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
            Prism::Network::Target Target;

            struct Request final
            {
                Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
                Prism::Network::Target Target;
            };

            [[nodiscard]] static auto Run(Request Value)
                -> boost::asio::awaitable<Prism::Shadowtls::Result<Prism::SharedTransmission>>;

            [[nodiscard]] auto operator()(std::span<const std::uint8_t>) const
                -> boost::asio::awaitable<Prism::Shadowtls::Result<Prism::SharedTransmission>>;
        };

        [[nodiscard]] auto ParseShadowtlsPort(std::string_view Value)
            -> std::optional<std::uint16_t>;

        [[nodiscard]] auto ParseShadowtlsHostPort(std::string_view Value)
            -> std::optional<ShadowtlsHostPort>;

    } // namespace detail

    [[nodiscard]] auto MakeConfiguredShadowtlsServerAccept(
        ShadowtlsCarrierOptions Options)
        -> std::expected<CarrierAcceptFn, ShadowtlsCarrierBuildError>;

} // namespace Prism::Composition::Recognition
