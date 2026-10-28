/** @file Network.cpp @brief Application 冷路径 UDP 目标异步解析实现。 */
#include <Prism/Application/Assembly/Network.hpp>

#include <boost/asio/ip/address.hpp>

#include <utility>
#include <variant>

namespace Prism::Application::Assembly
{

    auto ResolveUdpTarget(
        std::shared_ptr<Prism::Network::Dns::Resolver> DnsResolver,
        Prism::Network::Target Request)
        -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Prism::Fault::Failure>>
    {
        if (Request.Host.Empty() || Request.Port == 0U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (const auto Literal = Prism::Network::IpAddress(Request.Host))
        {
            co_return Net::ip::udp::endpoint(*Literal, Request.Port);
        }
        if (!DnsResolver)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::DnsFailed});
        }
        const auto *Domain = std::get_if<Prism::Network::DomainName>(&Request.Host.Get());
        if (Domain == nullptr)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Addresses = co_await DnsResolver->AsyncResolve(Domain->View());
        if (!Addresses)
        {
            co_return std::unexpected(Addresses.error());
        }
        if (Addresses->Empty())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::DnsFailed});
        }
        co_return Net::ip::udp::endpoint((*Addresses)[0], Request.Port);
    }

} // namespace Prism::Application::Assembly
