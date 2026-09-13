/**
 * @file Exchange.hpp
 * @brief DNS 上游单次收发与连接池交换细节
 * @details 只负责 Link 的 Send/Receive 和池化连接复用；查询报文解析、
 *          RCODE 和 Fallback/First/Fastest 策略由 Upstream 负责。
 */

#pragma once

#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <preview/Net/Dns/ConnPool.hpp>
#include <preview/Net/Dns/Transport.hpp>
#include <preview/Net/Dns/Types.hpp>

namespace Preview::Network::Dns::Detail
{

    /**
     * @brief 池化交换请求参数
     * @tparam Link 可池化的 DNS 传输
     */
    template <PoolableTransport Link>
    struct PooledExchangeRequest
    {
        ConnPool<Link> &Pool;
        std::string Key;
        boost::asio::ip::tcp::endpoint Endpoint;
        const Server &ServerConfig;
        std::span<const std::uint8_t> Wire;
    };

    /**
     * @brief 在已连接 Link 上完成一次发送和接收
     * @param link 已连接传输
     * @param Wire DNS 查询报文
     * @return DNS 应答字节或传输错误
     */
    template <typename Link>
    [[nodiscard]] inline auto ExchangeOnce(Link &LinkObject, std::span<const std::uint8_t> Wire)
        -> boost::asio::awaitable<EcResult<std::vector<std::uint8_t>>>
    {
        if (auto ErrorCode = co_await LinkObject.Send(Wire))
        {
            co_return std::unexpected(ErrorCode);
        }
        co_return co_await LinkObject.Receive();
    }

    /**
     * @brief 池化交换：复用失败时新建连接重试一次
     * @tparam Link 可池化的 DNS 传输
     * @tparam Factory 建连工厂
     * @param Request 池化交换参数
     * @param makeLink 建连工厂
     * @return DNS 应答字节或传输错误
     */
    template <PoolableTransport Link, typename Factory>
    [[nodiscard]] inline auto ExchangePooled(PooledExchangeRequest<Link> Request, Factory MakeLink)
        -> boost::asio::awaitable<EcResult<std::vector<std::uint8_t>>>
    {
        if (Request.ServerConfig.KeepAlive)
        {
            auto Lease = Request.Pool.Acquire(Request.Key);
            if (Lease.Conn)
            {
                if (auto Result = co_await ExchangeOnce(*Lease.Conn, Request.Wire))
                {
                    Request.Pool.Release(Request.Key, Lease.Conn);
                    co_return Result;
                }
            }
        }

        auto Fresh = co_await MakeLink(Request.Endpoint, Request.ServerConfig);
        if (!Fresh)
        {
            co_return std::unexpected(Fresh.error());
        }
        auto Result = co_await ExchangeOnce(**Fresh, Request.Wire);
        if (Result && Request.ServerConfig.KeepAlive)
        {
            Request.Pool.Release(Request.Key, *Fresh);
        }
        co_return Result;
    }

} // namespace Preview::Network::Dns::Detail
