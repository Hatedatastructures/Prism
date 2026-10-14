/**
 * @file Http2ClientTypes.hpp
 * @brief TrustTunnel HTTP/2 client 的正式参数与结果类型。
 * @details TLS context 与 ClientConfig 在 ConnectHttp2 完成前由调用者保活；上游和
 *          byte pool 按值转移给 factory owner。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/ssl/context.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <string_view>

namespace Preview::Trusttunnel
{

    struct Http2ConnectParameters final
    {
        SharedTransmission Upstream;
        boost::asio::ssl::context &SslContext;
        const ClientConfig &Config;
        std::string_view Target;
        std::uint16_t Port{0};
        std::string_view ServerName;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };

    using Http2ClientResult = std::expected<void, Preview::Fault::Failure>;

} // namespace Preview::Trusttunnel