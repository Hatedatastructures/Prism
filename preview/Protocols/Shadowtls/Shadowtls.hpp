/**
 * @file Shadowtls.hpp
 * @brief ShadowTLS v3 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，SessionId HMAC 认证 + 数据透传）
 * - 编解码/认证：Codec.hpp（SessionId 生成/校验 + 帧 HMAC + KDF）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Shadowtls/Codec.hpp>
#include <preview/Protocols/Shadowtls/Conn.hpp>
#include <preview/Protocols/Shadowtls/Types.hpp>

namespace Preview::Shadowtls
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief ShadowTLS 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端认证密码
        std::string password;
    };

    /**
     * @struct ServerConfig
     * @brief ShadowTLS 服务端配置
     * @details 控制服务端的行为：认证密码。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端认证密码
        std::string password;
    };

    /**
     * @struct ConnectParameters
     * @brief ShadowTLS 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；随机数视图和 Config 在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> ServerRandom;
        std::span<const std::uint8_t> ClientRandom;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 SessionId 认证握手
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.password);
        const auto Err = co_await C->WriteHandshake(Params.ServerRandom, Params.ClientRandom);
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
     * @brief 接收服务端流连接并完成 SessionId 认证校验
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(upstream), cfg.password);
        const auto Err = co_await C->ReadHandshake();
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

} // namespace Preview::Shadowtls
