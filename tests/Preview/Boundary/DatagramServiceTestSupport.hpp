/**
 * @file DatagramServiceTestSupport.hpp
 * @brief DatagramServiceTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <array>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Protocols/Socks5/AssociationFactory.hpp>
#include <Preview/Protocols/Vless/AssociationFactory.hpp>
#include <Preview/Protocols/Trojan/DatagramSession.hpp>
#include <Preview/Protocols/Vmess/DatagramSession.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Boundary/Contract/BoundaryDispatcher.hpp>
#include <Preview/Boundary/Quic/QuicPacketGateway.hpp>
#include <Preview/Boundary/Datagram/DatagramAssociation.hpp>
#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>
#include <Preview/Boundary/Datagram/DatagramListener.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Socks5/Conn.hpp>
#include <Preview/Protocols/Trojan/Dgram.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Network = Preview::Network;
    namespace Runtime = Preview::Runtime;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Vless = Preview::Vless;
    namespace Vmess = Preview::Vmess;
    using Udp = Net::ip::udp;
    using Tcp = Net::ip::tcp;
    using Preview::Error;
    using Preview::PreviewMockTransport;
    using Preview::SharedTransmission;
    using Preview::Testing::RunCoro;
    using Preview::Testing::TrafficRecorder;
    using Preview::Testing::MakeUuid;
    using Preview::Testing::UdpEchoServer;

    auto MakeContext(SharedTransmission Inbound) -> Middleware::Context
    {
        Middleware::Context ContextValue;
        ContextValue.Inbound() = std::move(Inbound);
        return ContextValue;
    }

    auto UdpEchoOnce(const std::shared_ptr<Udp::socket> &Socket) -> Net::awaitable<void>
    {
        std::array<std::byte, 65535> Payload{};
        Udp::endpoint Peer;
        boost::system::error_code ErrorCode;
        const auto Size = co_await Socket->async_receive_from(
            Net::buffer(Payload), Peer,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return;
        }
        co_await Socket->async_send_to(
            Net::buffer(Payload.data(), Size), Peer,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_return;
    }




















} // namespace

