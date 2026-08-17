/**
 * @file trusttunnel.hpp
 * @brief TrustTunnel 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / connect_packet（客户端）、
 *   accept / accept_packet（服务端）——认证握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，CONNECT 隧道）、
 *   dgram（包，dgram.hpp，HTTP/2 数据帧承载）
 * - 编解码/认证：codec.hpp（Basic Auth 构造/解析/校验）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/trusttunnel/codec.hpp>
#include <common/protocols/trusttunnel/conn.hpp>
#include <common/protocols/trusttunnel/dgram.hpp>
#include <common/protocols/trusttunnel/types.hpp>

namespace preview::trusttunnel
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief TrustTunnel 客户端配置
     * @details 控制客户端的行为：认证凭据。构造后只读。
     */
    struct client_config
    {
        /// 认证用户名
        std::string username;
        /// 认证密码
        std::string password;
    };

    /**
     * @struct server_config
     * @brief TrustTunnel 服务端配置
     * @details 控制服务端的行为：认证凭据。构造后只读。
     */
    struct server_config
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
     * @param target 目标主机
     * @param port 目标端口
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      std::string_view target, std::uint16_t port)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(std::move(upstream), cfg.username, cfg.password);
        const auto err = co_await c->write_handshake(target, port);
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
     * @brief 创建客户端 UDP 包连接（CONNECT 后包一层 dgram）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标主机
     * @param port 目标端口
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect_packet(shared_transmission upstream, const client_config &cfg,
                                             std::string_view target, std::uint16_t port)
        -> net::awaitable<std::pair<error, shared_dgram>>
    {
        auto [err, conn] = co_await connect(std::move(upstream), cfg, target, port);
        if (err != error::none)
        {
            co_return std::pair{err, shared_dgram{}};
        }
        co_return std::pair{error::none, std::make_shared<dgram>(std::move(conn))};
    }

    /**
     * @brief 接收服务端流连接并完成 CONNECT 认证
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的目标与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, std::string, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(std::move(upstream), cfg.username, cfg.password);
        std::string target;
        const auto err = co_await c->read_handshake(target);
        shared_conn conn;
        if (err == error::none)
        {
            conn = shared_conn(std::move(c));
        }
        else
        {
            conn = shared_conn{};
        }
        co_return std::tuple{err, std::move(target), std::move(conn)};
    }

    /**
     * @brief 接收服务端 UDP 包连接
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的目标与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept_packet(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, std::string, shared_dgram>>
    {
        auto [err, target, conn] = co_await accept(std::move(upstream), cfg);
        if (err != error::none)
        {
            co_return std::tuple{err, std::move(target), shared_dgram{}};
        }
        co_return std::tuple{error::none, std::move(target), std::make_shared<dgram>(std::move(conn))};
    }

} // namespace preview::trusttunnel
