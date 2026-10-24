/**
 * @file Vless.hpp
 * @brief VLESS 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp）、Dgram（包，Dgram.hpp）
 * - 数据面：UdpTunnel（UDP 命令数据面，UdpTunnel.hpp）
 * - 编解码：AddressCodec.hpp、RequestCodec.hpp、UdpCodec.hpp、
 *   BeastCodec.hpp；协议数据位于 Types.hpp
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <cstdint>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Vless/AddressCodec.hpp>
#include <Prism/Protocols/Vless/BeastCodec.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>
#include <Prism/Protocols/Vless/Conn.hpp>
#include <Prism/Protocols/Vless/Dgram.hpp>
#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vless/UdpTunnel.hpp>

namespace Prism::Vless
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
        Prism::SharedAuthenticator AuthenticatorOwner{};
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
    [[nodiscard]] auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp 命令握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 成功时返回包连接；失败时返回保留首个原生原因的 Failure
     */
    [[nodiscard]] auto ConnectPacket(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>;

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 成功时返回请求与协议连接；失败时返回完整 Failure
     */
    [[nodiscard]] auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>;

    /**
     * @brief 接收服务端 UDP 包连接（udp 命令）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 成功时返回请求与包连接；失败时返回完整 Failure
     */
    [[nodiscard]] auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>;

} // namespace Prism::Vless
