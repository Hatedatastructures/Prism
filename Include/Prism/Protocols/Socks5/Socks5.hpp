/**
 * @file Socks5.hpp
 * @brief SOCKS5 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp）、Dgram（包，Dgram.hpp）
 * - 数据面：UdpAssoc（真实 UDP 关联服务，UdpAssoc.hpp）
 * - 编解码：AddressCodec.hpp、AuthCodec.hpp、MessageCodec.hpp、
 *   TransportCodec.hpp、BeastCodec.hpp；协议数据位于 Types.hpp
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/AuthCodec.hpp>
#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <Prism/Protocols/Socks5/Conn.hpp>
#include <Prism/Protocols/Socks5/Dgram.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/Reply.hpp>
#include <Prism/Protocols/Socks5/TransportCodec.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>
#include <Prism/Protocols/Socks5/UdpAssoc.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Prism::Socks5
{

    /**
     * @struct ConnectParameters
     * @brief SOCKS5 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；Config 与 Target 仅在握手期间借用。
     * 该值对象不分配堆内存，适合在会话创建边界传递。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig& Config;
        const Address& Target;
        Command Cmd{Command::Connect};
    };

    struct AcceptedConnection final
    {
        Request RequestValue;
        SharedConn Connection;
    };

    struct AcceptedDatagram final
    {
        Request RequestValue;
        SharedDgram Connection;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成握手（sing DialConn 语义）
     * @param Params 客户端连接装配参数
     * @return 成功时返回拥有型协议连接；失败时返回完整 Failure。
     * @details 内部流程：创建 Conn → WriteHandshake 完成客户端
     * 完整握手（Greeting/方法选择/认证/请求/响应）。
     */
    [[nodiscard]] auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp_associate 握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] auto ConnectPacket(SharedTransmission Upstream, const ClientConfig& Config,
        const Address& Target) -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>;

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     * @details 内部流程：创建 Conn → ReadHandshake 完成服务端
     * 完整握手（Greeting/方法协商/认证/请求/响应）。
     */
    [[nodiscard]] auto Accept(SharedTransmission Upstream, const ServerConfig& Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>;

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] auto AcceptPacket(SharedTransmission Upstream, const ServerConfig& Config)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>;

} // namespace Prism::Socks5
