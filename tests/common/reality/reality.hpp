/**
 * @file reality.hpp
 * @brief Reality 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / accept ——认证握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，X25519 + HKDF + AEAD 认证）
 * - 编解码/密钥：codec.hpp（X25519 + auth_key 派生 + session_id seal/open）
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/reality/codec.hpp>
#include <common/reality/conn.hpp>
#include <common/reality/types.hpp>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

namespace psmtest::reality
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief Reality 客户端配置
     * @details 控制客户端的行为：X25519 密钥与短 ID。构造后只读。
     */
    struct client_config
    {
        /// 客户端 X25519 私钥（32 字节）
        std::array<std::uint8_t, key_len> private_key{};
        /// 短 ID（8 字节，内嵌 session_id）
        std::array<std::uint8_t, max_short_id_len> short_id{};
    };

    /**
     * @struct server_config
     * @brief Reality 服务端配置
     * @details 控制服务端的行为：X25519 私钥与短 ID 校验。构造后只读。
     */
    struct server_config
    {
        /// 服务端 X25519 私钥（32 字节）
        std::array<std::uint8_t, key_len> private_key{};
        /// 允许的短 ID（空 = 通配）
        std::array<std::uint8_t, max_short_id_len> short_id{};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param peer_public_key 服务端公钥（32 字节）
     * @param client_random 客户端随机数（40 字节）
     * @param hello ClientHello 原始消息（AAD）
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      std::span<const std::uint8_t> peer_public_key,
                                      std::span<const std::uint8_t> client_random,
                                      std::span<const std::uint8_t> hello)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.private_key);
        const auto err = co_await c->write_handshake(peer_public_key, client_random, hello,
                                                     cfg.short_id);
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c))
                                                    : shared_conn{}};
    }

    /**
     * @brief 接收服务端流连接并完成认证校验
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @param peer_public_key 客户端公钥（32 字节）
     * @param client_random 客户端随机数（40 字节）
     * @param hello ClientHello 原始消息（AAD）
     * @return 错误码、解析的短 ID 与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg,
                                     std::span<const std::uint8_t> peer_public_key,
                                     std::span<const std::uint8_t> client_random,
                                     std::span<const std::uint8_t> hello)
        -> net::awaitable<std::tuple<error, std::array<std::uint8_t, max_short_id_len>, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.private_key);
        std::array<std::uint8_t, max_short_id_len> short_id{};
        const auto err = co_await c->read_handshake(peer_public_key, client_random, hello,
                                                    short_id);
        co_return std::tuple{err, short_id,
                             err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

} // namespace psmtest::reality
