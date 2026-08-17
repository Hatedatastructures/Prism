/**
 * @file gun.hpp
 * @brief gRPC (gun) 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / accept ——CONNECT 握手在工厂内部完成
 * - 连接：conn（流，conn.hpp，CONNECT 握手 + 数据透传）
 * - 编解码：codec.hpp（protobuf varint + gun 帧编解码）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/gun/codec.hpp>
#include <common/protocols/gun/conn.hpp>
#include <common/protocols/gun/types.hpp>

namespace preview::gun
{

    /**
     * @brief 创建客户端流连接并完成 CONNECT 握手
     * @param upstream 上游传输（所有权移交）
     * @param host 目标主机
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, std::string_view host)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(std::move(upstream));
        const auto err = co_await c->write_handshake(host);
        shared_conn conn;
        if (err == error::none)
        {
            conn = shared_conn(std::move(c));
        }
        else
        {
            conn = shared_conn{};
        }
        co_return std::pair{err, std::move(conn)};
    }

    /**
     * @brief 接收服务端流连接并完成 CONNECT 握手
     * @param upstream 上游传输（所有权移交）
     * @return 错误码、解析的目标与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream)
        -> net::awaitable<std::tuple<error, std::string, shared_conn>>
    {
        auto c = std::make_shared<conn<>>(std::move(upstream));
        std::string host;
        const auto err = co_await c->read_handshake(host);
        shared_conn conn;
        if (err == error::none)
        {
            conn = shared_conn(std::move(c));
        }
        else
        {
            conn = shared_conn{};
        }
        co_return std::tuple{err, std::move(host), std::move(conn)};
    }

} // namespace preview::gun
