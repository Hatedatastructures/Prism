/**
 * @file Quic.hpp
 * @brief QUIC listener 的中立 UDP 发包能力与协议服务。
 */
#pragma once

#include <Prism/Contract/Services/DatagramEgress.hpp>
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/system/error_code.hpp>
#include <cstddef>
#include <memory>
#include <span>

namespace Prism::Contract
{
    /**
     * @brief Boundary 拥有共享 socket 并执行服务端 UDP 发送。
     * @details payload 借用至 awaitable 完成；调用在 listener executor 上序列化。
     *          结果保留 socket error_code；Stop/取消会以错误完成，socket 最终关闭仍归 Boundary。
     */
    class QuicDatagramSender
    {
    public:
        virtual ~QuicDatagramSender() = default;

        /** @brief 将 QUIC packet 发往 peer，并保留原生 socket 错误。 */
        [[nodiscard]] virtual auto SendTo(
            std::span<const std::byte> Payload,
            const boost::asio::ip::udp::endpoint& Peer)
            -> boost::asio::awaitable<boost::system::error_code> = 0;
    };

    /** @brief QUIC server 冷绑定时借用的 Boundary 资源，不转移 socket 最终关闭权。 */
    struct QuicListenerResources final
    {
        boost::asio::any_io_executor Executor;
        std::shared_ptr<boost::asio::ip::udp::socket> Socket;
        std::shared_ptr<boost::asio::ssl::context> Tls;
        std::shared_ptr<QuicDatagramSender> Sender;
    };

    /** @brief QUIC stream/datagram 协议实际需要的独立服务端口。 */
    struct QuicBindingServices final
    {
        QuicListenerResources Listener;
        std::shared_ptr<StreamEgress> Streams;
        std::shared_ptr<StreamRelay> Relay;
        std::shared_ptr<DatagramEgress> Datagrams;
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic;
        Prism::Diagnose::ContextState Trace{Prism::Diagnose::ContextState::Empty()};
    };
}