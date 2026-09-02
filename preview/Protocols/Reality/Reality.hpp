/**
 * @file Reality.hpp
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

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Reality/Codec.hpp>
#include <preview/Protocols/Reality/Conn.hpp>
#include <preview/Protocols/Reality/Types.hpp>

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
        std::array<std::uint8_t, MaxShortIdLen> ShortId{};
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
        std::array<std::uint8_t, MaxShortIdLen> ShortId{};
    };

    /**
     * @struct ConnectParameters
     * @brief Reality 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；其余字段在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> PeerPublicKey;
        const HandshakeParams &Params;
    };

    /**
     * @struct AcceptParameters
     * @brief Reality 服务端连接装配参数
     * @details Upstream 的所有权转移给新连接；其余字段在握手期间借用。
     */
    struct AcceptParameters
    {
        SharedTransmission Upstream;
        const ServerConfig &Config;
        std::span<const std::uint8_t> PeerPublicKey;
        const HandshakeParams &Params;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.private_key);
        const auto Err = co_await C->WriteHandshake(Params.PeerPublicKey, Params.Params);
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
     * @brief 接收服务端流连接并完成认证校验
     * @param Params 服务端连接装配参数
     * @return 错误码、解析的短 ID 与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(AcceptParameters Params)
        -> net::awaitable<std::tuple<Error, std::array<std::uint8_t, MaxShortIdLen>, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.private_key);
        std::array<std::uint8_t, MaxShortIdLen> ShortId{};
        const auto Err = co_await C->ReadHandshake(Params.PeerPublicKey, Params.Params, ShortId);
        SharedConn Conn;
        if (Err == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{Err, ShortId, std::move(Conn)};
    }

} // namespace Preview::Reality
