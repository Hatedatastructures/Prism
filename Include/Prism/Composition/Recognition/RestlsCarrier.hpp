/**
 * @file RestlsCarrier.hpp
 * @brief 配置驱动的 Restls 中间人 carrier 构造。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>

#include <cstdint>
#include <expected>
#include <string>

namespace Prism::Composition::Recognition
{

    namespace Core = Prism::Recognition;

    enum class RestlsCarrierBuildError : std::uint8_t
    {
        MissingPassword,
        MissingDial,
        InvalidDestination,
    };

    struct RestlsCarrierOptions final
    {
        std::string Host;
        std::string Password;
        std::string RestlsScript;
        bool Tls13{false};
        Prism::Middleware::Builtin::DialMiddleware::DialFn Dial;
    };

    [[nodiscard]] auto MakeConfiguredRestlsServerAccept(
        RestlsCarrierOptions Options) -> std::expected<CarrierAcceptFn, RestlsCarrierBuildError>;

} // namespace Prism::Composition::Recognition
