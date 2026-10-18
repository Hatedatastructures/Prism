/** @file Target.hpp @brief 协议私有 wire 地址到唯一正式网络目标的单次转换。 */
#pragma once
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Net/Target.hpp>
namespace Prism::Vmess::Detail
{
    /** @brief 借用解析后的 wire 地址；返回拥有目标或失败，无 I/O、取消和关闭副作用。 */
    [[nodiscard]] inline auto ToNetworkTarget(const Address& Input)
        -> std::expected<Prism::Network::Target, Prism::Fault::Failure>
    {
        Prism::Network::HostEncoding Encoding;
        switch (Input.Type)
        {
        case AddressType::Ipv4: Encoding = Prism::Network::HostEncoding::Ipv4Text; break;
        case AddressType::Ipv6: Encoding = Prism::Network::HostEncoding::Ipv6Bytes; break;
        case AddressType::Domain: Encoding = Prism::Network::HostEncoding::Domain; break;
        default: return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        }
        auto Host = Prism::Network::DecodeHost(Encoding, Input.Host);
        if (!Host) return std::unexpected(Host.error());
        return Prism::Network::Target{std::move(*Host), Input.Port, Prism::Network::RouteKind::Forward};
    }
}