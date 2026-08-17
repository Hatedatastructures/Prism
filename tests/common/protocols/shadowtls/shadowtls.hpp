/**
 * @file shadowtls.hpp
 * @brief ShadowTLS v3 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / accept ——认证握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，session_id HMAC 认证 + 数据透传）
 * - 编解码/认证：codec.hpp（session_id 生成/校验 + 帧 HMAC + KDF）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/shadowtls/codec.hpp>
#include <common/protocols/shadowtls/conn.hpp>
#include <common/protocols/shadowtls/types.hpp>

namespace preview::shadowtls
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief ShadowTLS 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct client_config
    {
        /// 客户端认证密码
        std::string password;
    };

    /**
     * @struct server_config
     * @brief ShadowTLS 服务端配置
     * @details 控制服务端的行为：认证密码。构造后只读。
     */
    struct server_config
    {
        /// 服务端认证密码
        std::string password;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 session_id 认证握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param server_random 服务端随机数（32 字节）
     * @param client_random 客户端随机数（32 字节）
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      std::span<const std::uint8_t> server_random,
                                      std::span<const std::uint8_t> client_random)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(std::move(upstream), cfg.password);
        const auto err = co_await c->write_handshake(server_random, client_random);
        shared_conn conn;
        if (err == error::none)
        {
            conn = shared_conn(std::move(c));
        }
        else
        {
            conn = shared_conn{};
        }
        co_return std::pair{err, std::move(conn)};
    }

    /**
     * @brief 接收服务端流连接并完成 session_id 认证校验
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(std::move(upstream), cfg.password);
        const auto err = co_await c->read_handshake();
        shared_conn conn;
        if (err == error::none)
        {
            conn = shared_conn(std::move(c));
        }
        else
        {
            conn = shared_conn{};
        }
        co_return std::pair{err, std::move(conn)};
    }

} // namespace preview::shadowtls
