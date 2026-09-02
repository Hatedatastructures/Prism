/**
 * @file Ws.hpp
 * @brief WebSocket 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——HTTP 升级握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，Upgrade 握手 + 数据透传）
 * - 编解码：Codec.hpp（Accept 计算 + 帧头解析/编码/掩码）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Ws/Codec.hpp>
#include <preview/Protocols/Ws/Conn.hpp>
#include <preview/Protocols/Ws/Types.hpp>

namespace Preview::Ws
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief WebSocket 客户端配置
     * @details 控制客户端的行为：目标主机。构造后只读。
     */
    struct ClientConfig
    {
        /// 目标主机（Host 头）
        std::string host;
        /// Sec-WebSocket-Key（base64 24 字符）
        std::string key{"dGhlIHNhbXBsZSBub25jZQ=="};
    };

    /**
     * @struct ServerConfig
     * @brief WebSocket 服务端配置
     * @details 控制服务端的行为。构造后只读。
     */
    struct ServerConfig
    {
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 Upgrade 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(upstream));
        const auto Err = co_await C->WriteHandshake(cfg.key, cfg.host);
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
     * @brief 接收服务端流连接并完成 Upgrade 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、客户端 Key 与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, std::string, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(upstream));
        std::string key;
        const auto Err = co_await C->ReadHandshake(key);
        SharedConn Conn;
        if (Err == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{Err, std::move(key), std::move(Conn)};
    }

} // namespace Preview::Ws
