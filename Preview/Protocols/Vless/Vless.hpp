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
#include <exception>
#include <expected>
#include <memory>
#include <string>
#include <utility>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Protocols/Vless/Dgram.hpp>
#include <Preview/Protocols/Vless/Types.hpp>
#include <Preview/Protocols/Vless/UdpTunnel.hpp>

namespace Preview::Vless
{

    /** @brief 服务端认证后唯一拥有请求与流连接的结果。 */
    struct AcceptedConnection final
    {
        RequestHeader Request;
        SharedConn Connection;
    };

    /** @brief 服务端 UDP 命令接受结果。 */
    struct AcceptedDatagram final
    {
        RequestHeader Request;
        SharedDgram Connection;
    };

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
        /// 认证器共享所有权；用于长期存活的 handler/Profile
        Preview::SharedAuthenticator AuthenticatorOwner{};
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
     * @return 成功时返回协议连接；失败时返回保留首个原生原因的 Failure
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Preview::Fault::Failure>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        /** @brief 预预约进入协议工厂的 carrier 失败退休，不替代 listener 入口准入。 */
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Params.Upstream);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::shared_ptr<Conn<>> C;
        auto Construction = std::expected<void, Preview::Fault::Failure>{};
        try
        {
            C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.uuid);
        }
        catch (...)
        {
            Construction = std::unexpected(Preview::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
        if (!Construction)
        {
            const auto Failure = Construction.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        if (const auto Tracked = Admission.Track(C); !Tracked)
        {
            const auto Failure = Tracked.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        auto Handshake = std::expected<void, Preview::Fault::Failure>{};
        try
        {
            Handshake = co_await C->WriteHandshake(Params.Target, Params.Cmd);
        }
        catch (...)
        {
            Handshake = std::unexpected(Preview::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
        if (!Handshake)
        {
            const auto Failure = Handshake.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        Admission.Release();
        co_return SharedConn(std::move(C));
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp 命令握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 成功时返回包连接；失败时返回保留首个原生原因的 Failure
     */
    [[nodiscard]] inline auto ConnectPacket(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::expected<SharedDgram, Preview::Fault::Failure>>
    {
        auto Result = co_await Connect(
            ConnectParameters{std::move(Upstream), Config, Target, Command::Udp});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        co_return std::make_shared<Dgram<>>(std::move(*Result));
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 成功时返回请求与协议连接；失败时返回完整 Failure
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Preview::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto C = std::make_shared<Conn<>>(
            std::move(Upstream),
            Config.uuid,
            Config.AuthenticatorOwner);
        // 流承载 UDP 的数据面由 UdpTunnel 按传输类型进行能力校验；
        // 握手阶段仍需保留命令信息，避免把不安全的裸流帧当作已建立会话。
        auto Handshake = co_await C->ReadHandshake(true, Config.EnableUdp, true);
        if (!Handshake)
        {
            co_return std::unexpected(Handshake.error());
        }
        co_return AcceptedConnection{std::move(*Handshake), SharedConn(std::move(C))};
    }

    /**
     * @brief 接收服务端 UDP 包连接（udp 命令）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 成功时返回请求与包连接；失败时返回完整 Failure
     */
    [[nodiscard]] inline auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedDatagram, Preview::Fault::Failure>>
    {
        auto Result = co_await Accept(std::move(Upstream), Config);
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        auto StreamConnection = std::move(Result->Connection);
        if (Result->Request.Cmd != Command::Udp)
        {
            const auto Rejected =
                Preview::Protocol::Common::FailureFromProtocolError(Error::BadMessage);
            (void)StreamConnection->Close();
            (void)co_await StreamConnection->Activity()->Drain();
            co_return std::unexpected(Rejected);
        }
        auto DatagramConnection = std::make_shared<Dgram<>>(
            std::move(StreamConnection));
        co_return AcceptedDatagram{std::move(Result->Request), std::move(DatagramConnection)};
    }

} // namespace Preview::Vless
