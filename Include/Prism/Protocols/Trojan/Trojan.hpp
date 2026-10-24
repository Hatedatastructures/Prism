/**
 * @file Trojan.hpp
 * @brief Trojan 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件）
 * - 连接：Conn（流，Conn.hpp）、Dgram（包，Dgram.hpp）
 * - 编解码：AddressCodec.hpp、CredentialCodec.hpp、RequestCodec.hpp、
 *   UdpCodec.hpp、BeastCodec.hpp；协议数据位于 Types.hpp
 * @note 对齐 mihomo/sing-*：TCP 流与 UDP 包为两种独立连接类型；
 *          工厂自由函数承担"创建 + 装配 + 握手编排"。
 * @note span 参数为视图（不持有生命周期），连接所有权经 shared_ptr
 *          管理；Close() 同步关闭，Release() 可转移所有权。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <string>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Trojan/AddressCodec.hpp>
#include <Prism/Protocols/Trojan/BeastCodec.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Trojan/UdpCodec.hpp>
#include <Prism/Protocols/Trojan/Conn.hpp>
#include <Prism/Protocols/Trojan/Dgram.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>

namespace Prism::Trojan
{

    /** @brief 服务端认证后唯一拥有请求与流连接的结果。 */
    struct AcceptedConnection final
    {
        RequestHeader Request;
        SharedConn Connection;
    };

    /** @brief 服务端 UDP_ASSOCIATE 接受结果。 */
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
     * @brief Trojan 客户端配置
     * @details 控制客户端的行为：密码（凭据派生）。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端密码（连接构造时派生 SHA224 hex 凭据）
        std::string Password;
    };

    /**
     * @struct ServerConfig
     * @brief Trojan 服务端配置
     * @details 控制服务端的行为：密码（凭据派生）与命令开关。
     * 构造后只读。
     */
    struct ServerConfig
    {
        /// 认证密码（连接时算 SHA224 hex 凭据）
        std::string Password;
        /// 是否允许 CONNECT 命令（TCP 转发）
        bool EnableTcp = true;
        /// 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
        bool EnableUdp = false;
        /// 是否允许 MUX 命令
        bool EnableMux = true;
        /// 认证器共享所有权；用于长期存活的 handler/Profile
        Prism::SharedAuthenticator AuthenticatorOwner{};
    };

    /**
     * @struct ConnectParameters
     * @brief Trojan 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；Config 与 Target 仅在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        const Address &Target;
        Command Cmd{Command::Connect};
    };

    /**
     * @brief 创建客户端流连接并完成握手（sing DialConn 语义）
     * @tparam T 传输类型（TransmissionLike 约束）
     * @param Params 客户端连接装配参数
     * @return 成功时返回协议连接；失败时返回保留首个原生原因的 Failure
     * @details 内部流程：创建 Conn → 注入凭据 → WriteHandshake 发送
     * 请求头（握手对调用方透明）。成功后连接持有 upstream。
     */
    [[nodiscard]] auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp_associate 握手
     * @tparam T 传输类型（TransmissionLike 约束）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 成功时返回包连接；失败时返回保留首个原生原因的 Failure
     * @details 先经 Connect 完成 udp_associate 握手，再包装为
     * 包连接（对齐 mihomo ListenPacketContext：握手后 NewPacketConn）。
     */
    [[nodiscard]] auto ConnectPacket(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>;

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @tparam T 传输类型（TransmissionLike 约束）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 成功时返回请求与协议连接；失败时返回完整 Failure
     * @details 内部流程：创建 Conn → 注入凭据 → ReadHandshake 解析
     * 请求头（凭据/CRLF/命令开关/atyp/尾部校验）。认证失败不发送
     * 响应，静默断开。
     */
    [[nodiscard]] auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>;

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @tparam T 传输类型（TransmissionLike 约束）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 成功时返回请求与包连接；失败时返回完整 Failure
     * @details 先经 Accept 完成流握手解析，再包装为包连接。
     */
    [[nodiscard]] auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>;

} // namespace Prism::Trojan
