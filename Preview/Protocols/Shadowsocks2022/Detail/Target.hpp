/** @file Target.hpp @brief 协议私有 wire 地址到唯一正式网络目标的单次转换。 */
#pragma once
#include <Preview/Protocols/Shadowsocks2022/Types.hpp>
#include <Preview/Net/Target.hpp>
namespace Preview::Shadowsocks2022::Detail
{
    /** @brief 借用解析后的 wire 地址；返回拥有目标或失败，无 I/O、取消和关闭副作用。 */
    [[nodiscard]] inline auto ToNetworkTarget(const Address& Input)
        -> std::expected<Preview::Network::Target, Preview::Fault::Failure>
    {
        Preview::Network::HostEncoding Encoding;
        switch (Input.Type)
        {
        case AddressType::Ipv4: Encoding = Preview::Network::HostEncoding::Ipv4Text; break;
        case AddressType::Ipv6: Encoding = Preview::Network::HostEncoding::Ipv6Bytes; break;
        case AddressType::Domain: Encoding = Preview::Network::HostEncoding::Domain; break;
        default: return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument, {}});
        }
        auto Host = Preview::Network::DecodeHost(Encoding, Input.Host);
        if (!Host) return std::unexpected(Host.error());
        return Preview::Network::Target{std::move(*Host), Input.Port, Preview::Network::RouteKind::Forward};
    }
}