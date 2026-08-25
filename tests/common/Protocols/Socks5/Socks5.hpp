/**
 * @file socks5.hpp
 * @brief SOCKS5 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp）、Dgram（包，Dgram.hpp）
 * - 数据面：UdpAssoc（真实 UDP 关联服务，UdpAssoc.hpp）
 * - 编解码（Codec.hpp）、纯数据（types.hpp）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Socks5/Codec.hpp>
#include <common/Protocols/Socks5/Conn.hpp>
#include <common/Protocols/Socks5/Dgram.hpp>
#include <common/Protocols/Socks5/Types.hpp>
#include <common/Protocols/Socks5/UdpAssoc.hpp>

namespace Preview::Socks5
{

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成握手（sing DialConn 语义）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @param cmd 命令（默认 CONNECT；UDP 数据面传 udp_associate）
     * @return 错误码与协议连接（失败时连接为空）
     * @details 内部流程：创建 Conn → WriteHandshake 完成客户端
     * 完整握手（Greeting/方法选择/认证/请求/响应）。
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg,
                                      const Address &Target, Command cmd = Command::Connect)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        Request req;
        req.Cmd = cmd;
        req.Target = Target;
        auto c = std::make_shared<Conn<>>(std::move(upstream));
        const auto err = co_await c->WriteHandshake(req, cfg);
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::pair{err, std::move(Conn)};
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp_associate 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto ConnectPacket(SharedTransmission upstream, const ClientConfig &cfg,
                                             const Address &Target)
        -> net::awaitable<std::pair<Error, SharedDgram>>
    {
        auto [err, Conn] = co_await Connect(std::move(upstream), cfg, Target, Command::UdpAssociate);
        if (err != Error::none)
        {
            co_return std::pair{err, SharedDgram{}};
        }
        co_return std::pair{Error::none, std::make_shared<Dgram<>>(std::move(Conn))};
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     * @details 内部流程：创建 Conn → ReadHandshake 完成服务端
     * 完整握手（Greeting/方法协商/认证/请求/响应）。
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, Request, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream));
        auto [err, req] = co_await c->ReadHandshake(cfg);
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{err, std::move(req), std::move(Conn)};
    }

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto AcceptPacket(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, Request, SharedDgram>>
    {
        auto [err, req, Conn] = co_await Accept(std::move(upstream), cfg);
        if (err != Error::none)
        {
            co_return std::tuple{err, std::move(req), SharedDgram{}};
        }
        co_return std::tuple{Error::none, std::move(req), std::make_shared<Dgram<>>(std::move(Conn))};
    }

} // namespace Preview::Socks5
