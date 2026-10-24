/**
 * @file Trusttunnel.hpp
 * @brief TrustTunnel 流与数据报连接工厂接口。
 */
#pragma once

#include <Prism/Protocols/Trusttunnel/TransportTypes.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <cstdint>
#include <string>

namespace Prism::Trusttunnel
{
    namespace Net = boost::asio;

    struct ConnectParameters final
    {
        SharedTransmission Upstream;
        ClientConfig Configuration;
        std::string Target;
        std::uint16_t Port{0};
    };

    struct AcceptedConnection final
    {
        std::string Target;
        SharedConn Connection;
    };

    struct AcceptedDatagram final
    {
        std::string Target;
        SharedDgram Datagram;
    };

    [[nodiscard]] auto Connect(ConnectParameters Parameters)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;
    [[nodiscard]] auto ConnectPacket(ConnectParameters Parameters)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>;
    [[nodiscard]] auto Accept(SharedTransmission Upstream, ServerConfig Configuration)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>;
    [[nodiscard]] auto AcceptPacket(SharedTransmission Upstream, ServerConfig Configuration)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>;
}
