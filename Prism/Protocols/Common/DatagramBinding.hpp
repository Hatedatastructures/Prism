/** @file DatagramBinding.hpp @brief 工厂向协议会话移交数据报服务和观察快照。 */
#pragma once
#include <Prism/Protocols/Common/DatagramObservation.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Target.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <expected>
#include <utility>

namespace Prism::Protocols
{
    struct DatagramBinding final
    {
        Prism::Contract::DatagramServices Services;
        DatagramObservation Observation;
    };

    /** @brief 按拥有配置解析协议地址；缺省仅接受字面 IP，域名依赖显式解析器。 */
    inline auto ResolveDatagram(const Prism::Contract::DatagramServices& Services,
                                Prism::Network::Target Target)
        -> boost::asio::awaitable<std::expected<
            boost::asio::ip::udp::endpoint, Prism::Fault::Failure>>
    {
        if (Target.Host.Empty() || Target.Port == 0)
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        if (Services.Resolve) co_return co_await Services.Resolve(std::move(Target));
        const auto Address = Prism::Network::IpAddress(Target.Host);
        if (!Address)
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        co_return boost::asio::ip::udp::endpoint(*Address, Target.Port);
    }
}
