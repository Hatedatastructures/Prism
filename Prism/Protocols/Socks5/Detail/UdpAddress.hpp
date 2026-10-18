/**
 * @file UdpAddress.hpp
 * @brief SOCKS5 UDP端点到协议BND和回复地址的唯一内部转换。
 */
#pragma once

#include <Prism/Protocols/Socks5/Types.hpp>
#include <boost/asio/ip/udp.hpp>

namespace Prism::Socks5::Detail
{
    /** @brief 同步复制端点地址及端口，结果拥有完整地址文本，不借用socket或挂起。 */
    [[nodiscard]] inline auto EndpointToAddress(
        const boost::asio::ip::udp::endpoint &Endpoint) -> Address
    {
        Address Output;
        Output.Type = AddressType::Ipv6;
        if (Endpoint.address().is_v4()) Output.Type = AddressType::Ipv4;
        Output.Host = Endpoint.address().to_string();
        Output.Port = Endpoint.port();
        return Output;
    }
}
