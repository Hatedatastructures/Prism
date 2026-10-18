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
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Unreliable.hpp>
#include <Prism/Protocols/Hysteria2/Codec.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Hysteria2/Conn.hpp>
#include <Prism/Protocols/Hysteria2/Dgram.hpp>
#include <Prism/Protocols/Hysteria2/Admission.hpp>
#include <Prism/Protocols/Hysteria2/StreamSession.hpp>
#include <Prism/Protocols/Hysteria2/DatagramSession.hpp>
#include <Prism/Protocols/Hysteria2/Http3Auth.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>
#include <Prism/Protocols/Quic/DatagramAdapter.hpp>

namespace Prism::Hysteria2
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
        /// 认证器共享所有权；用于长期存活的 QUIC handler
        Prism::SharedAuthenticator AuthenticatorOwner{};
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
        if (!Upstream)
        {
            co_return std::pair{Error::NotOpen, SharedConn{}};
        }
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
     * @return 拥有的数据报连接或保留原生类别和值的失败
     * @details 远端文本与配置按值移入协程帧；socket 在 Executor 上创建并配置。
     *          无 TCP 握手，半关闭和最终关闭归返回的数据报载体；配置失败时等待
     *          同一 socket 的 Close 与 Activity 退栈，公开结果保留配置首因。
     */
    [[nodiscard]] inline auto ConnectPacket(
        Net::any_io_executor Executor,
        std::string Remote,
        ClientConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        (void)Config;
        auto Datagram = std::make_shared<Prism::Transport::Unreliable>(Executor);
        co_await Net::dispatch(Datagram->Executor(), Net::use_awaitable);
        const auto Connected = Datagram->Connect(Remote);
        if (!Connected)
        {
            const auto Failure = Connected.error();
            (void)Datagram->Close();
            const auto Activity = Datagram->Activity();
            (void)co_await Activity->Drain();
            co_return std::unexpected(Failure);
        }
        co_return SharedDgram{std::make_shared<Dgram<>>(std::move(Datagram))};
    }

    /**
     * @brief 从已建立的 QUIC 数据报提供者创建客户端包连接
     * @param Provider 已认证 QUIC 会话的数据报提供者（所有权移交）
     * @param Config 客户端配置（QUIC 会话已完成认证时不再重复使用）
     * @return Hysteria2 包连接或无效提供者失败
     */
    [[nodiscard]] inline auto ConnectPacket(Prism::Quic::SharedDatagramProvider Provider,
                                             const ClientConfig &Config)
        -> std::expected<SharedDgram, Prism::Fault::Failure>
    {
        (void)Config;
        if (!Provider)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Transport = std::make_shared<Prism::Quic::DatagramAdapter>(std::move(Provider));
        return SharedDgram{std::make_shared<Dgram<>>(std::move(Transport), true)};
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
        if (!Upstream)
        {
            co_return std::tuple{Error::NotOpen, Message{}, SharedConn{}};
        }
        auto Connection = std::make_shared<Conn<>>(
            std::move(Upstream),
            Config.password,
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
     * @return 拥有的数据报连接或保留原生类别和值的失败
     * @details 绑定 UDP 端口监听，逐帧编解码；无 TCP 握手。
     */
    [[nodiscard]] inline auto AcceptPacket(
        Net::any_io_executor Executor,
        unsigned short Port,
        ServerConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        (void)Config;
        auto Datagram = std::make_shared<Prism::Transport::Unreliable>(Executor);
        co_await Net::dispatch(Datagram->Executor(), Net::use_awaitable);
        const auto Bound = Datagram->Bind(Port);
        if (!Bound)
        {
            const auto Failure = Bound.error();
            (void)Datagram->Close();
            const auto Activity = Datagram->Activity();
            (void)co_await Activity->Drain();
            co_return std::unexpected(Failure);
        }
        Datagram->AllowAnyPeer();
        co_return SharedDgram{std::make_shared<Dgram<>>(std::move(Datagram))};
    }

    /**
     * @brief 从已建立的 QUIC 数据报提供者创建服务端包连接
     * @param Provider 已认证 QUIC 会话的数据报提供者（所有权移交）
     * @param Config 服务端配置（QUIC 会话已完成认证时不再重复使用）
     * @return Hysteria2 包连接或无效提供者失败
     */
    [[nodiscard]] inline auto AcceptPacket(Prism::Quic::SharedDatagramProvider Provider,
                                            const ServerConfig &Config)
        -> std::expected<SharedDgram, Prism::Fault::Failure>
    {
        (void)Config;
        if (!Provider)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Transport = std::make_shared<Prism::Quic::DatagramAdapter>(std::move(Provider));
        return SharedDgram{std::make_shared<Dgram<>>(std::move(Transport), true)};
    }

} // namespace Prism::Hysteria2
