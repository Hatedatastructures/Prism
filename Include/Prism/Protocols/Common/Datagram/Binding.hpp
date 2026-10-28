/** @file Binding.hpp @brief 工厂向协议会话移交数据报服务和观察快照。 */
#pragma once
#include <Prism/Protocols/Common/Datagram/Observation.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Target.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <expected>

namespace Prism::Protocols
{
    struct DatagramBinding final
    {
        Prism::Contract::DatagramServices Services;
        DatagramObservation Observation;
    };

    /** @brief 按拥有配置解析协议地址；缺省仅接受字面 IP，域名依赖显式解析器。 */
    auto ResolveDatagram(const Prism::Contract::DatagramServices& Services,
                         Prism::Network::Target Target)
        -> boost::asio::awaitable<std::expected<
            boost::asio::ip::udp::endpoint, Prism::Fault::Failure>>;
}
