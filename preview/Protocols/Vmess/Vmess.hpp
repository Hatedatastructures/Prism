/**
 * @file Vmess.hpp
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

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>
#include <preview/Protocols/Vmess/Conn.hpp>
#include <preview/Protocols/Vmess/Dgram.hpp>
#include <preview/Protocols/Vmess/Types.hpp>

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

    /**
     * @struct ConnectParameters
     * @brief VMess 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；Config 与 Target 仅在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        const Address &Target;
        std::uint8_t Cmd{static_cast<std::uint8_t>(Command::Tcp)};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 AEAD 握手
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(Params.Config.uuid);
        const auto Err = co_await C->WriteHandshake(std::move(Params.Upstream), Params.Target, Params.Cmd);
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
     * @brief 使用默认 TCP 命令创建客户端流连接
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置（借用）
     * @param Target 目标地址（借用）
     * @return 错误码与协议连接
     */
    [[nodiscard]] inline auto Connect(SharedTransmission Upstream, const ClientConfig &Config,
                                      const Address &Target)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Result = co_await Connect(ConnectParameters{std::move(Upstream), Config, Target});
        co_return Result;
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
        auto [Err, Conn] = co_await Connect(ConnectParameters{
            std::move(upstream), cfg, Target, static_cast<std::uint8_t>(Command::Udp)});
        if (Err != Error::None)
        {
            co_return std::pair{Err, SharedDgram{}};
        }
        co_return std::pair{Error::None, std::make_shared<Dgram<>>(std::move(Conn))};
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
        auto C = std::make_shared<Conn<>>(cfg.uuid);
        auto [Err, req] = co_await C->ReadHandshake(std::move(upstream));
        SharedConn Conn;
        if (Err == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{Err, std::move(req), std::move(Conn)};
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
        auto [Err, req, Conn] = co_await Accept(std::move(upstream), cfg);
        if (Err != Error::None)
        {
            co_return std::tuple{Err, std::move(req), SharedDgram{}};
        }
        co_return std::tuple{Error::None, std::move(req), std::make_shared<Dgram<>>(std::move(Conn))};
    }

} // namespace Preview::Vmess
