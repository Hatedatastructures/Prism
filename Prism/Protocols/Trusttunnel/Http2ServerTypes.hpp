/**
 * @file Http2ServerTypes.hpp
 * @brief TrustTunnel HTTP/2 server factory 的公开输入与结果。
 * @details TLS context 在 AcceptHttp2 awaitable 完成前由调用者保活；Raw 与 immutable
 *          wire/auth binding 按值移交，成功结果拥有 accepted carrier。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/ssl/context.hpp>

#include <expected>
#include <memory>
#include <string>

namespace Prism::Trusttunnel
{

    using Http2ServerResult = std::expected<void, Prism::Fault::Failure>;

    struct Http2Accepted final
    {
        std::string Target;
        SharedTransmission Transport;
    };

    struct Http2AcceptRequest final
    {
        SharedTransmission Raw;
        boost::asio::ssl::context &SslContext;
        SharedWireAuthBinding Binding;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

} // namespace Prism::Trusttunnel