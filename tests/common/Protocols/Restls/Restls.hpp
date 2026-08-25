/**
 * @file restls.hpp
 * @brief Restls 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，BLAKE3 认证 + 数据透传）
 * - 编解码/认证：Codec.hpp（Secret 派生 + server_mask + auth_mac + mask）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Restls/Codec.hpp>
#include <common/Protocols/Restls/Conn.hpp>
#include <common/Protocols/Restls/Types.hpp>

namespace Preview::Restls
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief Restls 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端认证密码
        std::string password;
    };

    /**
     * @struct ServerConfig
     * @brief Restls 服务端配置
     * @details 控制服务端的行为：认证密码。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端认证密码
        std::string password;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param server_random 服务端随机数（32 字节）
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg,
                                      std::span<const std::uint8_t> server_random)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.password);
        const auto err = co_await c->WriteHandshake(server_random);
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
     * @brief 接收服务端流连接并完成认证握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @param server_random 服务端随机数（32 字节）
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg,
                                     std::span<const std::uint8_t> server_random)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.password);
        const auto err = co_await c->ReadHandshake(server_random);
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

} // namespace Preview::Restls
