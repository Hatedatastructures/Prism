/** @file DatagramBinding.hpp @brief 工厂向协议会话移交数据报服务和观察快照。 */
#pragma once
#include <Preview/Protocols/Common/DatagramObservation.hpp>
#include <Preview/Contract/Services/Datagram.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Target.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <expected>
#include <utility>

namespace Preview::Protocols
{
    struct DatagramBinding final
    {
        Preview::Contract::DatagramServices Services;
        DatagramObservation Observation;
    };

    /** @brief 按拥有配置解析协议地址；缺省仅接受字面 IP，域名依赖显式解析器。 */
    inline auto ResolveDatagram(const Preview::Contract::DatagramServices& Services,
                                Preview::Network::Target Target)
        -> boost::asio::awaitable<std::expected<
            boost::asio::ip::udp::endpoint, Preview::Fault::Failure>>
    {
        if (Services.Resolve) co_return co_await Services.Resolve(std::move(Target));
        const auto Address = Preview::Network::IpAddress(Target.Host);
        if (!Address || Target.Port == 0)
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
        co_return boost::asio::ip::udp::endpoint(*Address, Target.Port);
    }
}
