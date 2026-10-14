/** @file Datagram.hpp @brief 协议数据报解析、观察与超时服务。 */
#pragma once
#include <Preview/Net/Target.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <chrono>
#include <expected>
#include <functional>
#include <memory>

namespace Preview::Contract
{

    /**
     * @brief 解析函数拥有 resolver，按值接管完整 Target；协程取消传播至解析。
     * @details Traffic 共享 owner 随协议 session 存活，观察失败不得中断业务。
     */
    struct DatagramServices final
    {
        using ResolveFn = std::function<boost::asio::awaitable<
            std::expected<boost::asio::ip::udp::endpoint, Preview::Fault::Failure>>(
                Preview::Network::Target)>;
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        ResolveFn Resolve;
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic;
    };
}
