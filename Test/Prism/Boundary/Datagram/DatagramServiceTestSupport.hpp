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

#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/DatagramSession.hpp>
#include <Prism/Protocols/Vmess/DatagramSession.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Boundary/Contract/BoundaryDispatcher.hpp>
#include <Prism/Boundary/Quic/QuicPacketGateway.hpp>
#include <Prism/Boundary/Datagram/DatagramAssociation.hpp>
#include <Prism/Boundary/Datagram/DatagramClassifier.hpp>
#include <Prism/Boundary/Datagram/DatagramListener.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Socks5/Conn.hpp>
#include <Prism/Protocols/Trojan/Dgram.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Vless/Conn.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Middleware = Prism::Middleware;
    namespace Network = Prism::Network;
    namespace Runtime = Prism::Runtime;
    namespace Socks5 = Prism::Socks5;
    namespace Trojan = Prism::Trojan;
    namespace Vless = Prism::Vless;
    namespace Vmess = Prism::Vmess;
    using Udp = Net::ip::udp;
    using Tcp = Net::ip::tcp;
    using Prism::Error;
    using Prism::PrismMockTransport;
    using Prism::SharedTransmission;
    using Prism::Testing::RunCoro;
    using Prism::Testing::TrafficRecorder;
    using Prism::Testing::MakeUuid;
    using Prism::Testing::UdpEchoServer;

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
