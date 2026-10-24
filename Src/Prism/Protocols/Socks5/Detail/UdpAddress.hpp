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
    [[nodiscard]] auto EndpointToAddress(
        const boost::asio::ip::udp::endpoint& Endpoint) -> Address;
}
