/**
 * @file Socks5.hpp
 * @brief SOCKS5 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp）、Dgram（包，Dgram.hpp）
 * - 数据面：UdpAssoc（真实 UDP 关联服务，UdpAssoc.hpp）
 * - 编解码（Codec.hpp）、纯数据（types.hpp）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Socks5/Conn.hpp>
#include <preview/Protocols/Socks5/Dgram.hpp>
#include <preview/Protocols/Socks5/Types.hpp>
#include <preview/Protocols/Socks5/UdpAssoc.hpp>

namespace Preview::Socks5
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
        const ClientConfig &Config;
        const Address &Target;
        Command Cmd{Command::Connect};
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成握手（sing DialConn 语义）
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     * @details 内部流程：创建 Conn → WriteHandshake 完成客户端
     * 完整握手（Greeting/方法选择/认证/请求/响应）。
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        Request req;
        req.Cmd = Params.Cmd;
        req.Target = Params.Target;
        auto Connection = std::make_shared<Conn<>>(std::move(Params.Upstream));
        const auto ErrorCode = co_await Connection->WriteHandshake(req, Params.Config);
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
     * @brief 使用默认 CONNECT 命令创建客户端流连接
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置（借用）
     * @param Target 目标地址（借用）
     * @return 错误码与协议连接
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Result = co_await Connect(ConnectParameters{std::move(Upstream), Config, Target});
        co_return Result;
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp_associate 握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto ConnectPacket(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::pair<Error, SharedDgram>>
    {
        auto [ErrorCode, Connection] = co_await Connect(
            ConnectParameters{std::move(Upstream), Config, Target, Command::UdpAssociate});
        if (ErrorCode != Error::None)
        {
            co_return std::pair{ErrorCode, SharedDgram{}};
        }
        co_return std::pair{Error::None, std::make_shared<Dgram<>>(std::move(Connection))};
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     * @details 内部流程：创建 Conn → ReadHandshake 完成服务端
     * 完整握手（Greeting/方法协商/认证/请求/响应）。
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::tuple<Error, Request, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream));
        auto [ErrorCode, Request] = co_await Connection->ReadHandshake(Config);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Connection->Close();
        }
        co_return std::tuple{ErrorCode, std::move(Request), std::move(Result)};
    }

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::tuple<Error, Request, SharedDgram>>
    {
        auto [ErrorCode, Request, Connection] = co_await Accept(std::move(Upstream), Config);
        if (ErrorCode != Error::None)
        {
            co_return std::tuple{ErrorCode, std::move(Request), SharedDgram{}};
        }
        co_return std::tuple{
            Error::None,
            std::move(Request),
            std::make_shared<Dgram<>>(std::move(Connection))};
    }

} // namespace Preview::Socks5
