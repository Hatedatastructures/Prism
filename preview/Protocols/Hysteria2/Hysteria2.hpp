/**
 * @file Hysteria2.hpp
 * @brief Hysteria2 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，TCP 帧透传 + UDP 数据面）、
 *   Dgram（包，Dgram.hpp，逐帧编解码）
 * - 编解码/认证：Codec.hpp（帧编解码纯函数 + MakeAuthRequest +
 *   Serializer/Parser）
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Unreliable.hpp>
#include <preview/Protocols/Hysteria2/Codec.hpp>
#include <preview/Foundation/Authenticator.hpp>
#include <preview/Protocols/Hysteria2/Conn.hpp>
#include <preview/Protocols/Hysteria2/Dgram.hpp>
#include <preview/Protocols/Hysteria2/Types.hpp>
#include <preview/Protocols/Quic/DatagramAdapter.hpp>

namespace Preview::Hysteria2
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief Hysteria2 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端认证密码
        std::string password;
    };

    /**
     * @struct ServerConfig
     * @brief Hysteria2 服务端配置
     * @details 控制服务端的行为：认证密码。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端认证密码
        std::string password;
        /// 认证器（旧兼容字段；优先使用 AuthenticatorOwner）
        const Preview::Authenticator *Authenticator{nullptr};
        /// 认证器共享所有权；用于长期存活的 QUIC handler
        Preview::SharedAuthenticator AuthenticatorOwner{};

        [[nodiscard]] auto ResolveAuthenticator() const noexcept -> const Preview::Authenticator *
        {
            if (AuthenticatorOwner)
            {
                return AuthenticatorOwner.get();
            }
            return Authenticator;
        }
    };

    /**
     * @struct PacketResult
     * @brief Hysteria2 独立数据报工厂结果
     */
    struct PacketResult
    {
        Error Status{Error::None};
        SharedDgram Datagram{};

        [[nodiscard]] explicit operator bool() const noexcept
        {
            if (Status != Error::None)
            {
                return false;
            }
            return static_cast<bool>(Datagram);
        }
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream), Config.password);
        const auto ErrorCode = co_await Connection->WriteHandshake(Target);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Result = SharedConn{};
        }
        co_return std::pair{ErrorCode, std::move(Result)};
    }

    /**
     * @brief 创建客户端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param Executor 执行器
     * @param Remote 代理服务器 UDP 端点（主机:端口）
     * @param Config 客户端配置
     * @return 包连接（连接失败时为空）
     * @details 直接创建 UDP socket 连接服务器，逐帧编解码；
     * 无 TCP 握手。
     */
    [[nodiscard]] inline auto ConnectPacketResult(
        Net::any_io_executor Executor,
        const std::string &Remote,
        const ClientConfig &Config) -> PacketResult
    {
        (void)Config;
        auto Datagram = std::make_shared<Preview::Transport::Unreliable>(Executor);
        if (!Datagram->Connect(Remote))
        {
            return PacketResult{Error::BadAddress, {}};
        }
        return PacketResult{Error::None,
                            std::make_shared<Dgram<>>(std::move(Datagram))};
    }

    [[nodiscard]] inline auto ConnectPacket(
        Net::any_io_executor Executor,
        const std::string &Remote,
        const ClientConfig &Config) -> SharedDgram
    {
        return ConnectPacketResult(Executor, Remote, Config).Datagram;
    }

    /**
     * @brief 从已建立的 QUIC 数据报提供者创建客户端包连接
     * @param Provider 已认证 QUIC 会话的数据报提供者（所有权移交）
     * @param Config 客户端配置（QUIC 会话已完成认证时不再重复使用）
     * @return Hysteria2 包连接；提供者为空时返回空
     */
    [[nodiscard]] inline auto ConnectPacket(Preview::Quic::SharedDatagramProvider Provider,
                                             const ClientConfig &Config) -> SharedDgram
    {
        (void)Config;
        if (!Provider)
        {
            return nullptr;
        }
        auto Transport = std::make_shared<Preview::Quic::DatagramAdapter>(std::move(Provider));
        return std::make_shared<Dgram<>>(std::move(Transport), true);
    }

    /**
     * @brief 接收服务端流连接并完成认证握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的消息与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::tuple<Error, Message, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(
            std::move(Upstream),
            Config.password,
            Config.ResolveAuthenticator(),
            Config.AuthenticatorOwner);
        auto [ErrorCode, Request] = co_await Connection->ReadHandshake();
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Result = SharedConn{};
        }
        co_return std::tuple{ErrorCode, std::move(Request), std::move(Result)};
    }

    /**
     * @brief 接收服务端 UDP 包连接（独立 UDP socket）
     * @param Executor 执行器
     * @param Port 监听端口
     * @param Config 服务端配置
     * @return 包连接（绑定失败时为空）
     * @details 绑定 UDP 端口监听，逐帧编解码；无 TCP 握手。
     */
    [[nodiscard]] inline auto AcceptPacketResult(
        Net::any_io_executor Executor,
        unsigned short Port,
        const ServerConfig &Config) -> PacketResult
    {
        (void)Config;
        auto Datagram = std::make_shared<Preview::Transport::Unreliable>(Executor);
        if (!Datagram->Bind(Port))
        {
            return PacketResult{Error::IoError, {}};
        }
        Datagram->AllowAnyPeer();
        return PacketResult{Error::None,
                            std::make_shared<Dgram<>>(std::move(Datagram))};
    }

    [[nodiscard]] inline auto AcceptPacket(
        Net::any_io_executor Executor,
        unsigned short Port,
        const ServerConfig &Config) -> SharedDgram
    {
        return AcceptPacketResult(Executor, Port, Config).Datagram;
    }

    /**
     * @brief 从已建立的 QUIC 数据报提供者创建服务端包连接
     * @param Provider 已认证 QUIC 会话的数据报提供者（所有权移交）
     * @param Config 服务端配置（QUIC 会话已完成认证时不再重复使用）
     * @return Hysteria2 包连接；提供者为空时返回空
     */
    [[nodiscard]] inline auto AcceptPacket(Preview::Quic::SharedDatagramProvider Provider,
                                            const ServerConfig &Config) -> SharedDgram
    {
        (void)Config;
        if (!Provider)
        {
            return nullptr;
        }
        auto Transport = std::make_shared<Preview::Quic::DatagramAdapter>(std::move(Provider));
        return std::make_shared<Dgram<>>(std::move(Transport), true);
    }

} // namespace Preview::Hysteria2
