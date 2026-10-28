/** @file Binding.cpp @brief Common 数据报目标解析实现。 */

#include <Prism/Protocols/Common/Datagram/Binding.hpp>

#include <Prism/Net/HostText.hpp>

#include <utility>

namespace Prism::Protocols
{
    auto ResolveDatagram(
        const Prism::Contract::DatagramServices& Services,
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
} // namespace Prism::Protocols
