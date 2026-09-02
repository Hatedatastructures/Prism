/**
 * @file Vless.hpp
 * @brief VLESS 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp）、Dgram（包，Dgram.hpp）
 * - 数据面：UdpTunnel（UDP 命令数据面，UdpTunnel.hpp）
 * - 编解码（Codec.hpp）、纯数据（Types.hpp）
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
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Foundation/Authenticator.hpp>
#include <preview/Protocols/Vless/Conn.hpp>
#include <preview/Protocols/Vless/Dgram.hpp>
#include <preview/Protocols/Vless/Types.hpp>
#include <preview/Protocols/Vless/UdpTunnel.hpp>

namespace Preview::Vless
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief VLESS 客户端配置
     * @details 控制客户端的行为：UUID 认证。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端 UUID（16 字节，握手认证用）
        std::array<std::uint8_t, UuidLen> uuid{};
    };

    /**
     * @struct ServerConfig
     * @brief VLESS 服务端配置
     * @details 控制服务端的行为：UUID 校验与命令开关。构造后只读。
     */
    struct ServerConfig
    {
        /// 客户端 UUID（16 字节，凭据校验用）
        std::array<std::uint8_t, UuidLen> uuid{};
        /// 是否允许 UDP 命令（mux 连接除外）
        bool EnableUdp = true;
        /// 认证器（非拥有；nullptr = 静态比对 uuid）
        const Preview::Authenticator *Authenticator{nullptr};
    };

    /**
     * @struct ConnectParameters
     * @brief VLESS 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；Config 与 Target 仅在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        const Address &Target;
        Command Cmd{Command::Tcp};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成握手（sing DialConn 语义）
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.uuid);
        const auto Err = co_await C->WriteHandshake(Params.Target, Params.Cmd);
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
        (void)upstream;
        (void)cfg;
        (void)Target;
        co_return std::pair{Error::NotSupported, SharedDgram{}};
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, RequestHeader, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(upstream), cfg.uuid, cfg.Authenticator);
        // 流承载 UDP 的数据面由 UdpTunnel 按传输类型进行能力校验；
        // 握手阶段仍需保留命令信息，避免把不安全的裸流帧当作已建立会话。
        auto [Err, req] = co_await C->ReadHandshake(true, cfg.EnableUdp, true);
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
        -> net::awaitable<std::tuple<Error, RequestHeader, SharedDgram>>
    {
        (void)upstream;
        (void)cfg;
        co_return std::tuple{Error::NotSupported, RequestHeader{}, SharedDgram{}};
    }

} // namespace Preview::Vless
