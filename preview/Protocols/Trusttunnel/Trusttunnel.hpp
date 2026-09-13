/**
 * @file Trusttunnel.hpp
 * @brief TrustTunnel 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，CONNECT 隧道）、
 *   Dgram（包，Dgram.hpp，HTTP/2 数据帧承载）
 * - 编解码/认证：Codec.hpp（Basic Auth 构造/解析/校验）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Trusttunnel/Codec.hpp>
#include <preview/Protocols/Trusttunnel/Conn.hpp>
#include <preview/Protocols/Trusttunnel/Http2.hpp>
#include <preview/Protocols/Trusttunnel/Dgram.hpp>
#include <preview/Protocols/Trusttunnel/Types.hpp>

namespace Preview::Trusttunnel
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ConnectParameters
     * @brief TrustTunnel 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；Config 与 Target 视图在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::string_view Target;
        std::uint16_t Port;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 CONNECT 握手
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(
            std::move(Params.Upstream), Params.Config.username, Params.Config.password);
        const auto ErrorCode = co_await Connection->WriteHandshake(Params.Target, Params.Port);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Connection->Close();
        }
        co_return std::pair{ErrorCode, std::move(Result)};
    }

    /**
     * @brief 创建客户端 UDP 包连接（CONNECT 后包一层 Dgram）
     * @param Params 客户端连接装配参数
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto ConnectPacket(ConnectParameters Params)
        -> Net::awaitable<std::pair<Error, SharedDgram>>
    {
        auto [ErrorCode, Connection] = co_await Connect(std::move(Params));
        if (ErrorCode != Error::None)
        {
            co_return std::pair{ErrorCode, SharedDgram{}};
        }
        co_return std::pair{Error::None, std::make_shared<Dgram>(std::move(Connection))};
    }

    /**
     * @brief 接收服务端流连接并完成 CONNECT 认证
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的目标与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::tuple<Error, std::string, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(
            std::move(Upstream), Config.username, Config.password);
        std::string Target;
        const auto ErrorCode = co_await Connection->ReadHandshake(Target);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Connection->Close();
        }
        co_return std::tuple{ErrorCode, std::move(Target), std::move(Result)};
    }

    /**
     * @brief 接收服务端 UDP 包连接
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的目标与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::tuple<Error, std::string, SharedDgram>>
    {
        auto [ErrorCode, Target, Connection] = co_await Accept(std::move(Upstream), Config);
        if (ErrorCode != Error::None)
        {
            co_return std::tuple{ErrorCode, std::move(Target), SharedDgram{}};
        }
        co_return std::tuple{
            Error::None,
            std::move(Target),
            std::make_shared<Dgram>(std::move(Connection))};
    }

} // namespace Preview::Trusttunnel
