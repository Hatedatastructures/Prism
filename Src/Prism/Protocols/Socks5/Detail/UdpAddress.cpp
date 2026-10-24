/** @file UdpAddress.cpp @brief UDP endpoint 到 SOCKS5 wire 地址的转换。 */
#include "UdpAddress.hpp"

namespace Prism::Socks5::Detail
{

    auto EndpointToAddress(const boost::asio::ip::udp::endpoint& Endpoint) -> Address
    {
        Address Output;
        Output.Type = Endpoint.address().is_v4() ? AddressType::Ipv4 : AddressType::Ipv6;
        Output.Host = Endpoint.address().to_string();
        Output.Port = Endpoint.port();
        return Output;
    }

} // namespace Prism::Socks5::Detail
