/**
 * @file ws.hpp
 * @brief WebSocket 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / accept ——HTTP 升级握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，Upgrade 握手 + 数据透传）
 * - 编解码：codec.hpp（Accept 计算 + 帧头解析/编码/掩码）
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/stealth/ws/codec.hpp>
#include <common/stealth/ws/conn.hpp>
#include <common/stealth/ws/types.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

namespace psmtest::ws
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief WebSocket 客户端配置
     * @details 控制客户端的行为：目标主机。构造后只读。
     */
    struct client_config
    {
        /// 目标主机（Host 头）
        std::string host;
        /// Sec-WebSocket-Key（base64 24 字符）
        std::string key{"dGhlIHNhbXBsZSBub25jZQ=="};
    };

    /**
     * @struct server_config
     * @brief WebSocket 服务端配置
     * @details 控制服务端的行为。构造后只读。
     */
    struct server_config
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
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream));
        const auto err = co_await c->write_handshake(cfg.key, cfg.host);
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c))
                                                    : shared_conn{}};
    }

    /**
     * @brief 接收服务端流连接并完成 Upgrade 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、客户端 Key 与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, std::string, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream));
        std::string key;
        const auto err = co_await c->read_handshake(key);
        co_return std::tuple{err, std::move(key),
                             err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

} // namespace psmtest::ws
