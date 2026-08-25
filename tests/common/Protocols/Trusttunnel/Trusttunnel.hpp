/**
 * @file trusttunnel.hpp
 * @brief TrustTunnel 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，CONNECT 隧道）、
 *   Dgram（包，Dgram.hpp，HTTP/2 数据帧承载）
 * - 编解码/认证：Codec.hpp（Basic Auth 构造/解析/校验）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Trusttunnel/Codec.hpp>
#include <common/Protocols/Trusttunnel/Conn.hpp>
#include <common/Protocols/Trusttunnel/Dgram.hpp>
#include <common/Protocols/Trusttunnel/Types.hpp>

namespace Preview::Trusttunnel
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief TrustTunnel 客户端配置
     * @details 控制客户端的行为：认证凭据。构造后只读。
     */
    struct ClientConfig
    {
        /// 认证用户名
        std::string username;
        /// 认证密码
        std::string password;
    };

    /**
     * @struct ServerConfig
     * @brief TrustTunnel 服务端配置
     * @details 控制服务端的行为：认证凭据。构造后只读。
     */
    struct ServerConfig
    {
        /// 认证用户名
        std::string username;
        /// 认证密码
        std::string password;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 CONNECT 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标主机
     * @param port 目标端口
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg,
                                      std::string_view Target, std::uint16_t port)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.username, cfg.password);
        const auto err = co_await c->WriteHandshake(Target, port);
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
     * @brief 创建客户端 UDP 包连接（CONNECT 后包一层 Dgram）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标主机
     * @param port 目标端口
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto ConnectPacket(SharedTransmission upstream, const ClientConfig &cfg,
                                             std::string_view Target, std::uint16_t port)
        -> net::awaitable<std::pair<Error, SharedDgram>>
    {
        auto [err, Conn] = co_await Connect(std::move(upstream), cfg, Target, port);
        if (err != Error::none)
        {
            co_return std::pair{err, SharedDgram{}};
        }
        co_return std::pair{Error::none, std::make_shared<Dgram>(std::move(Conn))};
    }

    /**
     * @brief 接收服务端流连接并完成 CONNECT 认证
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的目标与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, std::string, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.username, cfg.password);
        std::string Target;
        const auto err = co_await c->ReadHandshake(Target);
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{err, std::move(Target), std::move(Conn)};
    }

    /**
     * @brief 接收服务端 UDP 包连接
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的目标与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto AcceptPacket(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, std::string, SharedDgram>>
    {
        auto [err, Target, Conn] = co_await Accept(std::move(upstream), cfg);
        if (err != Error::none)
        {
            co_return std::tuple{err, std::move(Target), SharedDgram{}};
        }
        co_return std::tuple{Error::none, std::move(Target), std::make_shared<Dgram>(std::move(Conn))};
    }

} // namespace Preview::Trusttunnel
