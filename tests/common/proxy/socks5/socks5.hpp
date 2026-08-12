/**
 * @file socks5.hpp
 * @brief SOCKS5 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / connect_packet（客户端）、
 *   accept / accept_packet（服务端）——握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp）、dgram（包，dgram.hpp）
 * - 编解码（codec.hpp）、纯数据（types.hpp）
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/socks5/codec.hpp>
#include <common/proxy/socks5/conn.hpp>
#include <common/proxy/socks5/dgram.hpp>
#include <common/proxy/socks5/types.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace psmtest::socks5
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief SOCKS5 客户端配置
     * @details 控制客户端的行为：认证开关与凭据。构造后只读。
     */
    struct client_config
    {
        /// 是否启用用户名/密码认证（RFC 1929）
        bool enable_auth = false;
        /// 认证用户名（enable_auth 为 true 时生效）
        std::string username;
        /// 认证密码（enable_auth 为 true 时生效）
        std::string password;
    };

    /**
     * @struct server_config
     * @brief SOCKS5 服务端配置
     * @details 控制服务端的行为：命令开关与认证凭据。构造后只读。
     */
    struct server_config
    {
        /// 是否允许 CONNECT 命令（TCP 转发）
        bool enable_tcp = true;
        /// 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
        bool enable_udp = true;
        /// 是否启用用户名/密码认证（RFC 1929）
        bool enable_auth = false;
        /// 认证用户名（enable_auth 为 true 时生效）
        std::string username;
        /// 认证密码（enable_auth 为 true 时生效）
        std::string password;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成握手（sing DialConn 语义）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @param cmd 命令（默认 CONNECT；UDP 数据面传 udp_associate）
     * @return 错误码与协议连接（失败时连接为空）
     * @details 内部流程：创建 conn → write_handshake 完成客户端
     * 完整握手（greeting/方法选择/认证/请求/响应）。
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      const address &target, command cmd = command::connect)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        request req;
        req.cmd = cmd;
        req.target = target;
        auto c = std::make_shared<conn>(std::move(upstream));
        const auto err = co_await c->write_handshake(req, cfg.enable_auth, cfg.username, cfg.password);
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c))
                                                    : shared_conn{}};
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp_associate 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect_packet(shared_transmission upstream,
                                             const client_config &cfg, const address &target)
        -> net::awaitable<std::pair<error, shared_dgram>>
    {
        auto [err, conn] =
            co_await connect(std::move(upstream), cfg, target, command::udp_associate);
        if (err != error::none)
            co_return std::pair{err, shared_dgram{}};
        co_return std::pair{error::none, std::make_shared<dgram>(std::move(conn))};
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     * @details 内部流程：创建 conn → read_handshake 完成服务端
     * 完整握手（greeting/方法协商/认证/请求/响应）。
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, request, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream));
        auto [err, req] = co_await c->read_handshake(cfg.enable_tcp, cfg.enable_udp,
                                                     cfg.enable_auth, cfg.username, cfg.password);
        co_return std::tuple{err, std::move(req),
                             err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept_packet(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, request, shared_dgram>>
    {
        auto [err, req, conn] = co_await accept(std::move(upstream), cfg);
        if (err != error::none)
            co_return std::tuple{err, std::move(req), shared_dgram{}};
        co_return std::tuple{error::none, std::move(req),
                             std::make_shared<dgram>(std::move(conn))};
    }

} // namespace psmtest::socks5
