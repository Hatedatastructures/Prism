/**
 * @file vmess.hpp
 * @brief VMess 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，chunk 加解密数据面）、
 *   Dgram（包，Dgram.hpp，chunk 即包）
 * - 编解码/密码学：Codec.hpp（认证头/请求头/响应头 + KDF + chunk + 握手）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <tuple>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Vmess/Codec.hpp>
#include <common/Protocols/Vmess/Conn.hpp>
#include <common/Protocols/Vmess/Dgram.hpp>
#include <common/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief VMess 客户端配置
     * @details 控制客户端的行为：UUID 认证。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端 UUID（16 字节，握手认证用）
        std::array<std::uint8_t, 16> uuid{};
    };

    /**
     * @struct ServerConfig
     * @brief VMess 服务端配置
     * @details 控制服务端的行为：UUID 校验。构造后只读。
     */
    struct ServerConfig
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
     * @param Target 目标地址
     * @param cmd 命令（默认 Tcp；UDP 数据面传 udp）
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg,
                                      const Address &Target, std::uint8_t cmd = static_cast<std::uint8_t>(Command::Tcp))
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(cfg.uuid);
        const auto err = co_await c->WriteHandshake(std::move(upstream), Target, cmd);
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
     * @brief 创建客户端 UDP 包连接并完成 udp 命令握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto ConnectPacket(SharedTransmission upstream, const ClientConfig &cfg,
                                             const Address &Target)
        -> net::awaitable<std::pair<Error, SharedDgram>>
    {
        auto [err, Conn] = co_await Connect(std::move(upstream), cfg, Target, static_cast<std::uint8_t>(Command::Udp));
        if (err != Error::none)
        {
            co_return std::pair{err, SharedDgram{}};
        }
        co_return std::pair{Error::none, std::make_shared<Dgram<>>(std::move(Conn))};
    }

    /**
     * @brief 接收服务端流连接并完成 AEAD 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, Message, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(cfg.uuid);
        auto [err, req] = co_await c->ReadHandshake(std::move(upstream));
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{err, std::move(req), std::move(Conn)};
    }

    /**
     * @brief 接收服务端 UDP 包连接（udp 命令）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto AcceptPacket(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, Message, SharedDgram>>
    {
        auto [err, req, Conn] = co_await Accept(std::move(upstream), cfg);
        if (err != Error::none)
        {
            co_return std::tuple{err, std::move(req), SharedDgram{}};
        }
        co_return std::tuple{Error::none, std::move(req), std::make_shared<Dgram<>>(std::move(Conn))};
    }

} // namespace Preview::Vmess
