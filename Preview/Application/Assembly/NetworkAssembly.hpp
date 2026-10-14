/**
 * @file NetworkAssembly.hpp
 * @brief Application 冷路径 UDP 目标解析装配。
 * @details 只负责把 typed target 与 resolver 组合成异步 UDP 解析；TCP 拨号统一由
 *          Preview::Network::Dialer::Dialer 提供，本文件不再保留重复解析/拨号路径。
 */

#pragma once

#include <Preview/Contract/Services/Datagram.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Target.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include <expected>
#include <memory>
#include <utility>

namespace Preview::Application::Assembly
{

    namespace Net = boost::asio;

    /**
     * @brief 把 typed UDP 目标解析为单个 udp endpoint；字面地址不经过 DNS。
     * @param DnsResolver 冷注入的解析 owner；失败保留 DNS 的原生 cause。
     * @param Request 按值接管的拥有型目标，数值端口不再格式化。
     * @return 成功的 endpoint 或完整 Failure；不保留 resolver、socket 或候选集合。
     */
    [[nodiscard]] inline auto ResolveUdpTarget(
        std::shared_ptr<Preview::Network::Dns::Resolver> DnsResolver,
        Preview::Network::Target Request)
        -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Preview::Fault::Failure>>
    {
        if (Request.Host.Empty() || Request.Port == 0U)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        }
        if (const auto Literal = Preview::Network::IpAddress(Request.Host))
        {
            co_return Net::ip::udp::endpoint(*Literal, Request.Port);
        }
        if (!DnsResolver)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::DnsFailed});
        }
        const auto *Domain = std::get_if<Preview::Network::DomainName>(&Request.Host.Get());
        if (Domain == nullptr)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        }
        const auto Addresses = co_await DnsResolver->AsyncResolve(Domain->View());
        if (!Addresses)
        {
            co_return std::unexpected(Addresses.error());
        }
        if (Addresses->Empty())
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::DnsFailed});
        }
        co_return Net::ip::udp::endpoint((*Addresses)[0], Request.Port);
    }

} // namespace Preview::Application::Assembly
