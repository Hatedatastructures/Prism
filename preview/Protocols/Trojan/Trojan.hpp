/**
 * @file Trojan.hpp
 * @brief Trojan 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件）
 * - 连接：Conn（流，Conn.hpp）、Dgram（包，Dgram.hpp）
 * - 编解码（Codec.hpp）、纯数据（Types.hpp）
 * @note 对齐 mihomo/sing-*：TCP 流与 UDP 包为两种独立连接类型；
 *          工厂自由函数承担"创建 + 装配 + 握手编排"。
 * @note span 参数为视图（不持有生命周期），连接所有权经 shared_ptr
 *          管理；Close() 同步关闭，Release() 可转移所有权。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Foundation/Authenticator.hpp>
#include <preview/Protocols/Trojan/Conn.hpp>
#include <preview/Protocols/Trojan/Dgram.hpp>
#include <preview/Protocols/Trojan/Types.hpp>

namespace Preview::Trojan
{

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
        std::string password;
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
        std::string password;
        /// 是否允许 CONNECT 命令（TCP 转发）
        bool EnableTcp = true;
        /// 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
        bool EnableUdp = false;
        /// 认证器（非拥有；nullptr = 静态比对 password）
        const Preview::Authenticator *Authenticator{nullptr};
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
     * @return 错误码与协议连接（失败时连接为空）
     * @details 内部流程：创建 Conn → 注入凭据 → WriteHandshake 发送
     * 请求头（握手对调用方透明）。成功后连接持有 upstream。
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.password);
        const auto Err = co_await C->WriteHandshake(Params.Target, Params.Cmd);
        SharedConn Conn;
        if (Err == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::pair{Err, std::move(Conn)};
    }

    /**
     * @brief 使用默认 CONNECT 命令创建客户端流连接
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置（借用）
     * @param Target 目标地址（借用）
     * @return 错误码与协议连接
     */
    [[nodiscard]] inline auto Connect(SharedTransmission Upstream, const ClientConfig &Config,
                                      const Address &Target)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Result = co_await Connect(ConnectParameters{std::move(Upstream), Config, Target});
        co_return Result;
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp_associate 握手
     * @tparam T 传输类型（TransmissionLike 约束）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     * @details 先经 Connect 完成 udp_associate 握手，再包装为
     * 包连接（对齐 mihomo ListenPacketContext：握手后 NewPacketConn）。
     */
    [[nodiscard]] inline auto ConnectPacket(SharedTransmission upstream, const ClientConfig &cfg,
                                             const Address &Target)
        -> net::awaitable<std::pair<Error, SharedDgram>>
    {
        auto [Err, Conn] = co_await Connect(
            ConnectParameters{std::move(upstream), cfg, Target, Command::UdpAssociate});
        if (Err != Error::None)
        {
            co_return std::pair{Err, SharedDgram{}};
        }
        co_return std::pair{Error::None, std::make_shared<Dgram<>>(std::move(Conn))};
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @tparam T 传输类型（TransmissionLike 约束）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     * @details 内部流程：创建 Conn → 注入凭据 → ReadHandshake 解析
     * 请求头（凭据/CRLF/命令开关/atyp/尾部校验）。认证失败不发送
     * 响应，静默断开。
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, RequestHeader, SharedConn>>
    {
        auto C = std::make_shared<Conn<>>(std::move(upstream), cfg.password, cfg.Authenticator);
        auto [Err, req] = co_await C->ReadHandshake(cfg.EnableTcp, cfg.EnableUdp);
        SharedConn Conn;
        if (Err == Error::None)
        {
            Conn = SharedConn(std::move(C));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{Err, std::move(req), std::move(Conn)};
    }

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @tparam T 传输类型（TransmissionLike 约束）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     * @details 先经 Accept 完成流握手解析，再包装为包连接。
     */
    [[nodiscard]] inline auto AcceptPacket(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, RequestHeader, SharedDgram>>
    {
        auto [Err, req, Conn] = co_await Accept(std::move(upstream), cfg);
        if (Err != Error::None)
        {
            co_return std::tuple{Err, std::move(req), SharedDgram{}};
        }
        co_return std::tuple{Error::None, std::move(req), std::make_shared<Dgram<>>(std::move(Conn))};
    }

} // namespace Preview::Trojan
