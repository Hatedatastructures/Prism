/**
 * @file tuic.hpp
 * @brief Tuic 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / connect_packet（客户端）、
 *   accept / accept_packet（服务端）——握手在工厂内部完成
 * - 配置：client_config / server_config（本文件，字段分开定义）
 * - 连接：conn（流，conn.hpp，TCP 帧透传 + UDP 数据面）、
 *   dgram（包，dgram.hpp，packet 帧编解码）
 * - 编解码：codec.hpp（帧编解码纯函数 + serializer/parser）
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/udp_transmission.hpp>
#include <common/proxy/tuic/codec.hpp>
#include <common/proxy/tuic/conn.hpp>
#include <common/proxy/tuic/dgram.hpp>
#include <common/proxy/tuic/types.hpp>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

namespace psmtest::tuic
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief Tuic 客户端配置
     * @details 控制客户端的行为：UUID 与令牌认证。构造后只读。
     */
    struct client_config
    {
        /// 客户端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// 客户端令牌（密码）
        std::string password;
    };

    /**
     * @struct server_config
     * @brief Tuic 服务端配置
     * @details 控制服务端的行为：UUID 与令牌校验。构造后只读。
     */
    struct server_config
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
     * @brief 创建客户端流连接并完成 connect 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      const address &target)
    -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.uuid);
        const auto err = co_await c->write_handshake(target);
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c))
                                                    : shared_conn{}};
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
    [[nodiscard]] inline auto connect_packet(net::any_io_executor ex, const std::string &remote,
                                             const client_config &cfg) -> shared_dgram
    {
        auto udp = std::make_shared<udp_transmission>(ex);
        if (!udp->connect(remote))
            return nullptr;
        return std::make_shared<dgram>(std::move(udp));
    }

    /**
     * @brief 接收服务端流连接并完成 connect 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的消息与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
    -> net::awaitable<std::tuple<error, message, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.uuid);
        auto [err, req] = co_await c->read_handshake();
        co_return std::tuple{err, std::move(req),
                             err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

    /**
     * @brief 接收服务端 UDP 包连接（独立 UDP socket）
     * @param ex 执行器
     * @param port 监听端口
     * @param cfg 服务端配置
     * @return 包连接（绑定失败时为空）
     * @details 绑定 UDP 端口监听，packet 帧编解码；无 TCP 握手。
     */
    [[nodiscard]] inline auto accept_packet(net::any_io_executor ex, unsigned short port,
                                            const server_config &cfg) -> shared_dgram
    {
        auto udp = std::make_shared<udp_transmission>(ex);
        if (!udp->bind(port))
            return nullptr;
        return std::make_shared<dgram>(std::move(udp));
    }

} // namespace psmtest::tuic
