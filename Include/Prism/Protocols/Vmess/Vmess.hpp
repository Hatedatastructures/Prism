/**
 * @file Vmess.hpp
 * @brief VMess 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   AcceptSession（服务端唯一握手入口）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，chunk 加解密数据面）、
 *   Dgram（包，Dgram.hpp，chunk 即包）
 * - 编解码/密码学：AuthCrypto.hpp、AuthKdf.hpp、AuthId.hpp、AuthHeader.hpp、
 *   ChunkCodec.hpp、RequestCodec.hpp、ResponseCodec.hpp
 */

#pragma once
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <expected>
#include <memory>
#include <variant>
#include <cstdint>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Protocols/Vmess/AuthCrypto.hpp>
#include <Prism/Protocols/Vmess/AuthKdf.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/ResponseCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Protocols/Vmess/Conn.hpp>
#include <Prism/Protocols/Vmess/Dgram.hpp>

namespace Prism::Vmess
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
        Prism::SharedAuthenticator AuthenticatorOwner{};
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
    [[nodiscard]] auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp 命令握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @return 成功时返回包连接；失败时返回保留首个原生原因的 Failure
     */
    [[nodiscard]] auto ConnectPacket(SharedTransmission upstream, const ClientConfig &cfg,
                                             const Address &Target)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>;

    /**
     * @brief 接收 VMess 服务端会话并完成一次 AEAD 握手。
     * @param upstream 上游传输（所有权移交）；连接与数据报活动均沿该 owner 关闭和 drain。
     * @param cfg 服务端 UUID、认证 owner 与协议命令策略；只在握手期间借用。
     * @return 一个带请求的 stream 或 datagram owner；失败时保留完整领域/native 原因。
     * @details 本函数是唯一服务端握手入口。UDP command 返回 AcceptedDatagram，TCP/MUX
     *          返回 AcceptedConnection；调用者不得再按另一个 Accept/AcceptPacket 入口重做握手。
     */
    [[nodiscard]] auto AcceptSession(SharedTransmission upstream, const ServerConfig &cfg)
        -> Net::awaitable<std::expected<AcceptedSession, Prism::Fault::Failure>>;

} // namespace Prism::Vmess
