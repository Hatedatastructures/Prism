/**
 * @file anytls.hpp
 * @brief AnyTLS 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / accept ——认证握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，认证帧 + 数据透传）
 * - 编解码/认证：codec.hpp（密码哈希 + 认证帧编解码）
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/anytls/codec.hpp>
#include <common/anytls/conn.hpp>
#include <common/anytls/types.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

namespace psmtest::anytls
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief AnyTLS 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct client_config
    {
        /// 客户端认证密码
        std::string password;
    };

    /**
     * @struct server_config
     * @brief AnyTLS 服务端配置
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
     * @brief 创建客户端流连接并完成认证握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.password);
        const auto err = co_await c->write_handshake();
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c))
                                                    : shared_conn{}};
    }

    /**
     * @brief 接收服务端流连接并完成认证校验
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.password);
        const auto err = co_await c->read_handshake();
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c))
                                                    : shared_conn{}};
    }

} // namespace psmtest::anytls
