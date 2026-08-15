/**
 * @file vmess.hpp
 * @brief VMess 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / connect_packet（客户端）、
 *   accept / accept_packet（服务端）——握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，chunk 加解密数据面）、
 *   dgram（包，dgram.hpp，chunk 即包）
 * - 编解码/密码学：codec.hpp（认证头/请求头/响应头 + KDF + chunk + 握手）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <tuple>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/vmess/codec.hpp>
#include <common/proxy/vmess/conn.hpp>
#include <common/proxy/vmess/dgram.hpp>
#include <common/proxy/vmess/types.hpp>

namespace psmtest::vmess
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief VMess 客户端配置
     * @details 控制客户端的行为：UUID 认证。构造后只读。
     */
    struct client_config
    {
        /// 客户端 UUID（16 字节，握手认证用）
        std::array<std::uint8_t, 16> uuid{};
    };

    /**
     * @struct server_config
     * @brief VMess 服务端配置
     * @details 控制服务端的行为：UUID 校验。构造后只读。
     */
    struct server_config
    {
        /// 客户端 UUID（16 字节，握手校验用）
        std::array<std::uint8_t, 16> uuid{};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 AEAD 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @param cmd 命令（默认 tcp；UDP 数据面传 udp）
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      const address &target, command cmd = command::tcp)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(cfg.uuid);
        const auto err = co_await c->write_handshake(std::move(upstream), target, cmd);
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp 命令握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect_packet(shared_transmission upstream, const client_config &cfg,
                                             const address &target)
        -> net::awaitable<std::pair<error, shared_dgram>>
    {
        auto [err, conn] = co_await connect(std::move(upstream), cfg, target, command::udp);
        if (err != error::none)
        {
            co_return std::pair{err, shared_dgram{}};
        }
        co_return std::pair{error::none, std::make_shared<dgram<>>(std::move(conn))};
    }

    /**
     * @brief 接收服务端流连接并完成 AEAD 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, message, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(cfg.uuid);
        auto [err, req] = co_await c->read_handshake(std::move(upstream));
        co_return std::tuple{err, std::move(req),
                             err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

    /**
     * @brief 接收服务端 UDP 包连接（udp 命令）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept_packet(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, message, shared_dgram>>
    {
        auto [err, req, conn] = co_await accept(std::move(upstream), cfg);
        if (err != error::none)
        {
            co_return std::tuple{err, std::move(req), shared_dgram{}};
        }
        co_return std::tuple{error::none, std::move(req), std::make_shared<dgram<>>(std::move(conn))};
    }

} // namespace psmtest::vmess
