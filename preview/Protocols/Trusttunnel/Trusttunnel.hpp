/**
 * @file Trusttunnel.hpp
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

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Trusttunnel/Codec.hpp>
#include <preview/Protocols/Trusttunnel/Conn.hpp>
#include <preview/Protocols/Trusttunnel/Dgram.hpp>
#include <preview/Protocols/Trusttunnel/Types.hpp>

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

    /**
     * @struct ConnectParameters
     * @brief TrustTunnel 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；Config 与 Target 视图在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::string_view Target;
        std::uint16_t Port;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 CONNECT 握手
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.username,
                                          Params.Config.password);
        const auto Err = co_await C->WriteHandshake(Params.Target, Params.Port);
        SharedConn Conn;
        if (Err == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::pair{Err, std::move(Conn)};
    }

    /**
     * @brief 创建客户端 UDP 包连接（CONNECT 后包一层 Dgram）
     * @param Params 客户端连接装配参数
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto ConnectPacket(ConnectParameters Params)
        -> net::awaitable<std::pair<Error, SharedDgram>>
    {
        auto [Err, Conn] = co_await Connect(std::move(Params));
        if (Err != Error::None)
        {
            co_return std::pair{Err, SharedDgram{}};
        }
        co_return std::pair{Error::None, std::make_shared<Dgram>(std::move(Conn))};
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
        auto C = std::make_shared<Conn<>>(std::move(upstream), cfg.username, cfg.password);
        std::string Target;
        const auto Err = co_await C->ReadHandshake(Target);
        SharedConn Conn;
        if (Err == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{Err, std::move(Target), std::move(Conn)};
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
        auto [Err, Target, Conn] = co_await Accept(std::move(upstream), cfg);
        if (Err != Error::None)
        {
            co_return std::tuple{Err, std::move(Target), SharedDgram{}};
        }
        co_return std::tuple{Error::None, std::move(Target), std::make_shared<Dgram>(std::move(Conn))};
    }

} // namespace Preview::Trusttunnel
