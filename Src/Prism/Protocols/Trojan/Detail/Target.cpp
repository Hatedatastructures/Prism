/** @file Target.cpp @brief Trojan wire 地址到正式网络目标的转换。 */
#include "Target.hpp"

namespace Prism::Trojan::Detail
{

    auto ToNetworkTarget(const Address& Input)
        -> std::expected<Prism::Network::Target, Prism::Fault::Failure>
    {
        Prism::Network::HostEncoding Encoding;
        switch (Input.Type)
        {
        case AddressType::Ipv4:
            Encoding = Prism::Network::HostEncoding::Ipv4Text;
            break;
        case AddressType::Ipv6:
            Encoding = Prism::Network::HostEncoding::Ipv6Bytes;
            break;
        case AddressType::Domain:
            Encoding = Prism::Network::HostEncoding::Domain;
            break;
        default:
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        }
        auto Host = Prism::Network::DecodeHost(Encoding, Input.Host);
        if (!Host)
        {
            return std::unexpected(Host.error());
        }
        return Prism::Network::Target{
            std::move(*Host), Input.Port, Prism::Network::RouteKind::Forward};
    }

} // namespace Prism::Trojan::Detail
