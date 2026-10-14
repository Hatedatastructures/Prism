/**
 * @file Tuic.hpp
 * @brief TUIC 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，TCP 帧透传 + UDP 数据面）、
 *   Dgram（包，Dgram.hpp，packet 帧编解码）
 * - 编解码：Codec.hpp（帧编解码纯函数 + Serializer/Parser）
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <Preview/Account/Credential.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Quic/DatagramAdapter.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Transport/Unreliable.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Protocols/Tuic/Admission.hpp>
#include <Preview/Protocols/Tuic/Conn.hpp>
#include <Preview/Protocols/Tuic/Dgram.hpp>
#include <Preview/Protocols/Tuic/Types.hpp>

namespace Preview::Tuic
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief TUIC 客户端配置
     * @details 控制客户端的行为：UUID 与令牌认证。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// 客户端密码（TLS exporter context）
        std::string password;
        /// TUIC v5 独立 uni stream
        SharedTransmission AuthStream;
        /// 当前 QUIC TLS 会话的 exporter
        KeyingMaterialExporter Exporter;
    };

    /**
     * @struct ServerConfig
     * @brief TUIC 服务端配置
     * @details 控制服务端的行为：UUID 与令牌校验。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// TLS exporter context（密码）
        std::string password;
        /// 账户目录使用的静态 typed 凭据（跨认证挂起点持有）
        std::shared_ptr<const Preview::Account::Credential> Credential{};
        /// TUIC v5 客户端认证 uni stream
        SharedTransmission AuthStream;
        /// 当前 QUIC TLS 会话的 exporter
        KeyingMaterialExporter Exporter;
        /// 认证器共享所有权
        Preview::SharedAuthenticator AuthenticatorOwner{};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 Connect 握手
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
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream), Config.uuid);
        const auto TargetValue = Target;
        auto AuthStream = Config.AuthStream;
        const auto Exporter = Config.Exporter;
        const auto Password = Config.password;
        const auto AuthenticationError = co_await Connection->WriteAuthentication(
            std::move(AuthStream),
            Exporter,
            Password);
        if (AuthenticationError != Error::None)
        {
            co_return std::pair{AuthenticationError, SharedConn{}};
        }
        const auto ErrorCode = co_await Connection->WriteHandshake(TargetValue);
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
        -> Net::awaitable<std::expected<SharedDgram, Preview::Fault::Failure>>
    {
        (void)Config;
        auto Datagram = std::make_shared<Preview::Transport::Unreliable>(Executor);
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
     * @return TUIC 包连接或无效提供者失败
     */
    [[nodiscard]] inline auto ConnectPacket(Preview::Quic::SharedDatagramProvider Provider,
                                             const ClientConfig &Config)
        -> std::expected<SharedDgram, Preview::Fault::Failure>
    {
        (void)Config;
        if (!Provider)
        {
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        auto Transport = std::make_shared<Preview::Quic::DatagramAdapter>(std::move(Provider));
        return SharedDgram{std::make_shared<Dgram<>>(std::move(Transport))};
    }

    /**
     * @brief 接收服务端流连接并完成 Connect 握手
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
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream),
                                                   Config.uuid,
                                                   Config.AuthenticatorOwner);
        auto AuthStream = Config.AuthStream;
        ServerAuthenticationMaterial AuthenticationMaterial{
            .Exporter = Config.Exporter,
            .ExporterContext = Config.password,
            .Credential = Config.Credential};
        const auto AuthenticationError = co_await Connection->ReadAuthentication(
            std::move(AuthStream),
            std::move(AuthenticationMaterial));
        if (AuthenticationError != Error::None)
        {
            co_return std::tuple{AuthenticationError, Message{}, SharedConn{}};
        }
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
     * @details 绑定 UDP 端口监听，packet 帧编解码；无 TCP 握手。
     */
    [[nodiscard]] inline auto AcceptPacket(
        Net::any_io_executor Executor,
        unsigned short Port,
        ServerConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Preview::Fault::Failure>>
    {
        (void)Config;
        auto Datagram = std::make_shared<Preview::Transport::Unreliable>(Executor);
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
     * @return TUIC 包连接或无效提供者失败
     */
    [[nodiscard]] inline auto AcceptPacket(Preview::Quic::SharedDatagramProvider Provider,
                                            const ServerConfig &Config)
        -> std::expected<SharedDgram, Preview::Fault::Failure>
    {
        (void)Config;
        if (!Provider)
        {
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        auto Transport = std::make_shared<Preview::Quic::DatagramAdapter>(std::move(Provider));
        return SharedDgram{std::make_shared<Dgram<>>(std::move(Transport))};
    }

} // namespace Preview::Tuic
