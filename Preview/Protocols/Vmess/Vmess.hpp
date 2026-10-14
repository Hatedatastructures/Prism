/**
 * @file Vmess.hpp
 * @brief VMess 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   AcceptSession（服务端唯一握手入口）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，chunk 加解密数据面）、
 *   Dgram（包，Dgram.hpp，chunk 即包）
 * - 编解码/密码学：Codec.hpp（认证头/请求头/响应头 + KDF + chunk + 握手）
 */

#pragma once
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <utility>
#include <variant>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>
#include <Preview/Protocols/Vmess/Conn.hpp>
#include <Preview/Protocols/Vmess/Dgram.hpp>
#include <Preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    namespace Net = boost::asio;

    /** @brief 服务端认证后唯一拥有请求与流连接的结果。 */
    struct AcceptedConnection final
    {
        Message Request;
        SharedConn Connection;
    };

    /** @brief 服务端 UDP command 接受结果。 */
    struct AcceptedDatagram final
    {
        Message Request;
        SharedDgram Connection;
    };

    /** @brief 一次 VMess server handshake 的唯一有线会话结果。 */
    using AcceptedSession = std::variant<AcceptedConnection, AcceptedDatagram>;

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
     * @details 控制服务端的行为：UUID 校验与 UDP command 开关。构造后只读。
     */
    struct ServerConfig
    {
        /// 客户端 UUID（16 字节，握手校验用）
        std::array<std::uint8_t, 16> uuid{};
        /// 认证器共享所有权
        Preview::SharedAuthenticator AuthenticatorOwner{};
        /// 是否允许 UDP command（false 时在发送握手响应前拒绝）
        bool EnableUdp = true;
        /// 是否允许 MUX command
        bool EnableMux = true;

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
        Command Cmd{Command::Tcp};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 AEAD 握手
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
            C = std::make_shared<Conn<>>(ConnOptions{
                .Executor = Params.Upstream->Executor(), .Uuid = Params.Config.uuid});
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
            Handshake = co_await C->WriteHandshake(
                std::move(Params.Upstream), Params.Target, Params.Cmd);
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
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @return 成功时返回包连接；失败时返回保留首个原生原因的 Failure
     */
    [[nodiscard]] inline auto ConnectPacket(SharedTransmission upstream, const ClientConfig &cfg,
                                             const Address &Target)
        -> Net::awaitable<std::expected<SharedDgram, Preview::Fault::Failure>>
    {
        auto Result = co_await Connect(ConnectParameters{
            std::move(upstream), cfg, Target, Command::Udp});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        co_return std::make_shared<Dgram<>>(std::move(*Result));
    }

    /**
     * @brief 接收 VMess 服务端会话并完成一次 AEAD 握手。
     * @param upstream 上游传输（所有权移交）；连接与数据报活动均沿该 owner 关闭和 drain。
     * @param cfg 服务端 UUID、认证 owner 与协议命令策略；只在握手期间借用。
     * @return 一个带请求的 stream 或 datagram owner；失败时保留完整领域/native 原因。
     * @details 本函数是唯一服务端握手入口。UDP command 返回 AcceptedDatagram，TCP/MUX
     *          返回 AcceptedConnection；调用者不得再按另一个 Accept/AcceptPacket 入口重做握手。
     */
    [[nodiscard]] inline auto AcceptSession(SharedTransmission upstream, const ServerConfig &cfg)
        -> Net::awaitable<std::expected<AcceptedSession, Preview::Fault::Failure>>
    {
        if (!upstream)
        {
            co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto C = std::make_shared<Conn<>>(ConnOptions{
            .Executor = upstream->Executor(), .Uuid = cfg.uuid, .AuthenticatorOwner = cfg.AuthenticatorOwner});
        auto Handshake = co_await C->ReadHandshake(
            std::move(upstream), cfg.EnableUdp, cfg.EnableMux);
        if (!Handshake)
        {
            co_return std::unexpected(Handshake.error());
        }
        if (Handshake->Cmd == CmdUdp)
        {
            auto Datagram = std::make_shared<Dgram<>>(SharedConn(C));
            co_return AcceptedSession{AcceptedDatagram{
                std::move(*Handshake), std::move(Datagram)}};
        }
        co_return AcceptedSession{AcceptedConnection{
            std::move(*Handshake), SharedConn(std::move(C))}};
    }

} // namespace Preview::Vmess
