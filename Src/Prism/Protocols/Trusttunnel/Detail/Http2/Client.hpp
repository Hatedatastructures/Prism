/**
 * @file Client.hpp
 * @brief TrustTunnel HTTP/2 客户端 TLS 与 CONNECT 私有操作接口。
 */
#pragma once

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Client/Types.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <expected>

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;
    struct Http2TlsClientRequest;

    using Http2TlsResult = std::expected<
        Prism::Transport::Encrypted::SharedStream,
        Prism::Fault::Failure>;

    [[nodiscard]] auto RunHttp2TlsHandshake(
        Prism::Transport::Encrypted::SharedStream Stream)
        -> Net::awaitable<boost::system::error_code>;

    [[nodiscard]] auto RetireHttp2TlsFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Fault::Failure Cause,
        Prism::SharedTransmission Recovered) -> Net::awaitable<Http2TlsResult>;

    [[nodiscard]] auto ConnectHttp2Tls(
        Http2TlsClientRequest Request,
        Prism::Contract::InboundAdmission &Admission) -> Net::awaitable<Http2TlsResult>;

    [[nodiscard]] auto ConnectHttp2Core(
        Http2ConnectParameters Parameters,
        Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>;
}
