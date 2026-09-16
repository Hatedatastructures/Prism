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

#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Protocols/Vless/Dgram.hpp>
#include <Preview/Protocols/Vless/Types.hpp>
#include <Preview/Protocols/Vless/UdpTunnel.hpp>

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
        /// 认证器（旧兼容字段；优先使用 AuthenticatorOwner）
        const Preview::Authenticator *Authenticator{nullptr};
        /// 认证器共享所有权；用于长期存活的 handler/Profile
        Preview::SharedAuthenticator AuthenticatorOwner{};

        /**
         * @brief 获取服务端认证器
         * @return 优先返回共享所有权中的认证器，否则返回兼容的非拥有指针
         * @note 返回值不转移认证器所有权。
         */
        [[nodiscard]] auto ResolveAuthenticator() const noexcept
            -> const Preview::Authenticator *
        {
            if (AuthenticatorOwner)
            {
                return AuthenticatorOwner.get();
            }
            return Authenticator;
        }
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
        -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        if (!Params.Upstream)
        {
            co_return std::pair{Error::NotOpen, SharedConn{}};
        }
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
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target)
        -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Result = co_await Connect(ConnectParameters{std::move(Upstream), Config, Target});
        co_return Result;
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp 命令握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto ConnectPacket(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::pair<Error, SharedDgram>>
    {
        if (!Upstream)
        {
            co_return std::pair{Error::NotOpen, SharedDgram{}};
        }
        auto C = std::make_shared<Conn<>>(std::move(Upstream), Config.uuid);
        const auto Err = co_await C->WriteHandshake(Target, Command::Udp);
        if (Err != Error::None)
        {
            co_return std::pair{Err, SharedDgram{}};
        }
        co_return std::pair{Error::None,
                            std::make_shared<Dgram<>>(std::move(C), Target, true)};
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::tuple<Error, RequestHeader, SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::tuple{Error::NotOpen, RequestHeader{}, SharedConn{}};
        }
        auto C = std::make_shared<Conn<>>(
            std::move(Upstream),
            Config.uuid,
            Config.ResolveAuthenticator(),
            Config.AuthenticatorOwner);
        // 流承载 UDP 的数据面由 UdpTunnel 按传输类型进行能力校验；
        // 握手阶段仍需保留命令信息，避免把不安全的裸流帧当作已建立会话。
        auto [ErrorCode, RequestValue] = co_await C->ReadHandshake(true, Config.EnableUdp, true);
        SharedConn Conn;
        if (ErrorCode == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{ErrorCode, std::move(RequestValue), std::move(Conn)};
    }

    /**
     * @brief 接收服务端 UDP 包连接（udp 命令）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::tuple<Error, RequestHeader, SharedDgram>>
    {
        if (!Upstream)
        {
            co_return std::tuple{Error::NotOpen, RequestHeader{}, SharedDgram{}};
        }
        auto C = std::make_shared<Conn<>>(
            std::move(Upstream),
            Config.uuid,
            Config.ResolveAuthenticator(),
            Config.AuthenticatorOwner);
        auto [ErrorCode, RequestValue] = co_await C->ReadHandshake(true, Config.EnableUdp, true);
        if (ErrorCode != Error::None)
        {
            co_return std::tuple{ErrorCode, RequestHeader{}, SharedDgram{}};
        }
        if (RequestValue.Cmd != Command::Udp)
        {
            co_return std::tuple{Error::BadMessage, RequestHeader{}, SharedDgram{}};
        }
        co_return std::tuple{
            Error::None,
            RequestValue,
            std::make_shared<Dgram<>>(std::move(C), RequestValue.Target, true)};
    }

} // namespace Preview::Vless
