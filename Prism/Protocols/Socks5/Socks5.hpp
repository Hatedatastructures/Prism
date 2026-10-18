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
#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Socks5/Codec.hpp>
#include <Prism/Protocols/Socks5/Conn.hpp>
#include <Prism/Protocols/Socks5/Dgram.hpp>
#include <Prism/Protocols/Socks5/Reply.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>
#include <Prism/Protocols/Socks5/UdpAssoc.hpp>

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
        const ClientConfig &Config;
        const Address &Target;
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
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(
                Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Params.Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        Request RequestValue;
        RequestValue.Cmd = Params.Cmd;
        RequestValue.Target = Params.Target;
        std::shared_ptr<Conn<>> Connection;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Connection = std::make_shared<Conn<>>(std::move(Params.Upstream));
        }
        catch (...)
        {
            CreationFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (CreationFailure)
        {
            co_return std::unexpected(co_await Admission.Retire(*CreationFailure));
        }
        if (const auto Tracked = Admission.Track(Connection); !Tracked)
        {
            const auto Failure = Tracked.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        auto Handshake = std::expected<void, Prism::Fault::Failure>{};
        try
        {
            Handshake = co_await Connection->WriteHandshake(RequestValue, Params.Config);
        }
        catch (...)
        {
            Handshake = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        if (!Handshake)
        {
            const auto Failure = Handshake.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        Admission.Release();
        co_return SharedConn(std::move(Connection));
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
        const Address &Target)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        auto Connection = co_await Connect(
            ConnectParameters{std::move(Upstream), Config, Target, Command::UdpAssociate});
        if (!Connection)
        {
            co_return std::unexpected(Connection.error());
        }
        co_return std::make_shared<Dgram<>>(std::move(*Connection));
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
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream));
        auto Handshake = std::expected<Request, Prism::Fault::Failure>{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError})};
        try
        {
            Handshake = co_await Connection->ReadHandshake(Config);
        }
        catch (...)
        {
            Handshake = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        if (!Handshake)
        {
            (void)Connection->Close();
            co_return std::unexpected(Handshake.error());
        }
        co_return AcceptedConnection{std::move(*Handshake), SharedConn(std::move(Connection))};
    }

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     */
    [[nodiscard]] inline auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>
    {
        auto Accepted = co_await Accept(std::move(Upstream), Config);
        if (!Accepted)
        {
            co_return std::unexpected(Accepted.error());
        }
        if (Accepted->RequestValue.Cmd != Command::UdpAssociate)
        {
            (void)Accepted->Connection->Close();
            co_return std::unexpected(
                Prism::Protocol::Common::FailureFromProtocolError(Error::BadMessage));
        }
        co_return AcceptedDatagram{
            std::move(Accepted->RequestValue),
            std::make_shared<Dgram<>>(std::move(Accepted->Connection))};
    }

} // namespace Prism::Socks5
