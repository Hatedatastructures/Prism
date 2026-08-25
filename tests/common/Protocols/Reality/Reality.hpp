/**
 * @file reality.hpp
 * @brief Reality 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，X25519 + HKDF + AEAD 认证）
 * - 编解码/密钥：Codec.hpp（X25519 + AuthKey 派生 + SessionId Seal/Open）
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
#include <common/Protocols/Reality/Codec.hpp>
#include <common/Protocols/Reality/Conn.hpp>
#include <common/Protocols/Reality/Types.hpp>

namespace Preview::Reality
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief Reality 客户端配置
     * @details 控制客户端的行为：X25519 密钥与短 ID。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端 X25519 私钥（32 字节）
        std::array<std::uint8_t, KeyLen> private_key{};
        /// 短 ID（8 字节，内嵌 SessionId）
        std::array<std::uint8_t, MaxShortIdLen> short_id{};
    };

    /**
     * @struct ServerConfig
     * @brief Reality 服务端配置
     * @details 控制服务端的行为：X25519 私钥与短 ID 校验。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端 X25519 私钥（32 字节）
        std::array<std::uint8_t, KeyLen> private_key{};
        /// 允许的短 ID（空 = 通配）
        std::array<std::uint8_t, MaxShortIdLen> short_id{};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param peer_public_key 服务端公钥（32 字节）
     * @param params 握手参数（client_random + hello + short_id）
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg,
                                      std::span<const std::uint8_t> peer_public_key,
                                      const HandshakeParams &params)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.private_key);
        const auto err = co_await c->WriteHandshake(peer_public_key, params);
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
     * @brief 接收服务端流连接并完成认证校验
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @param peer_public_key 客户端公钥（32 字节）
     * @param params 握手参数（client_random + hello）
     * @return 错误码、解析的短 ID 与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg,
                                     std::span<const std::uint8_t> peer_public_key,
                                     const HandshakeParams &params)
        -> net::awaitable<std::tuple<Error, std::array<std::uint8_t, MaxShortIdLen>, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.private_key);
        std::array<std::uint8_t, MaxShortIdLen> short_id{};
        const auto err = co_await c->ReadHandshake(peer_public_key, params, short_id);
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{err, short_id, std::move(Conn)};
    }

} // namespace Preview::Reality
