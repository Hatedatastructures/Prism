/**
 * @file TcpPair.hpp
 * @brief SOCKS5 UDP 测试共享的本地 TCP 控制连接。
 * @details socket 由调用方 coroutine frame 持有，避免 move-only socket 经 coroutine 返回帧转移。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace Prism::Socks5UdpTestSupport
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct TcpPair final
    {
        explicit TcpPair(Net::any_io_executor Executor)
            : Client(Executor), Server(Executor)
        {
        }

        Tcp::socket Client;
        Tcp::socket Server;
    };

    [[nodiscard]] inline auto MakeTcpPair(Net::io_context& Io, TcpPair& Pair)
        -> Net::awaitable<void>
    {
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        co_await Pair.Client.async_connect(Acceptor.local_endpoint(), Net::use_awaitable);
        co_await Acceptor.async_accept(Pair.Server, Net::use_awaitable);
        Acceptor.close();
    }
}
