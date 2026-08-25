/**
 * @file tuic.hpp
 * @brief Tuic 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，TCP 帧透传 + UDP 数据面）、
 *   Dgram（包，Dgram.hpp，packet 帧编解码）
 * - 编解码：Codec.hpp（帧编解码纯函数 + Serializer/Parser）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Transport/Unreliable.hpp>
#include <common/Protocols/Tuic/Codec.hpp>
#include <common/Protocols/Tuic/Conn.hpp>
#include <common/Protocols/Tuic/Dgram.hpp>
#include <common/Protocols/Tuic/Types.hpp>

namespace Preview::Tuic
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief Tuic 客户端配置
     * @details 控制客户端的行为：UUID 与令牌认证。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// 客户端令牌（密码）
        std::string password;
    };

    /**
     * @struct ServerConfig
     * @brief Tuic 服务端配置
     * @details 控制服务端的行为：UUID 与令牌校验。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// 服务端令牌（密码）
        std::string password;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 Connect 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg,
                                      const Address &Target) -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.uuid);
        const auto err = co_await c->WriteHandshake(Target);
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::pair{err, std::move(Conn)};
    }

    /**
     * @brief 创建客户端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param ex 执行器
     * @param remote 代理服务器 UDP 端点（host:port）
     * @param cfg 客户端配置
     * @return 包连接（连接失败时为空）
     * @details 直接创建 UDP socket 连接服务器，packet 帧编解码；
     * 无 TCP 握手。
     */
    [[nodiscard]] inline auto ConnectPacket(net::any_io_executor ex, const std::string &remote,
                                             const ClientConfig &cfg) -> SharedDgram
    {
        auto udp = std::make_shared<Preview::Transport::Unreliable>(ex);
        if (!udp->Connect(remote))
        {
            return nullptr;
        }
        return std::make_shared<Dgram<>>(std::move(udp));
    }

    /**
     * @brief 接收服务端流连接并完成 Connect 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的消息与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, Message, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream), cfg.uuid);
        auto [err, req] = co_await c->ReadHandshake();
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{err, std::move(req), std::move(Conn)};
    }

    /**
     * @brief 接收服务端 UDP 包连接（独立 UDP socket）
     * @param ex 执行器
     * @param port 监听端口
     * @param cfg 服务端配置
     * @return 包连接（绑定失败时为空）
     * @details 绑定 UDP 端口监听，packet 帧编解码；无 TCP 握手。
     */
    [[nodiscard]] inline auto AcceptPacket(net::any_io_executor ex, unsigned short port,
                                            const ServerConfig &cfg) -> SharedDgram
    {
        auto udp = std::make_shared<Preview::Transport::Unreliable>(ex);
        if (!udp->Bind(port))
        {
            return nullptr;
        }
        return std::make_shared<Dgram<>>(std::move(udp));
    }

} // namespace Preview::Tuic
