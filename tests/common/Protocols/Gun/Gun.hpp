/**
 * @file gun.hpp
 * @brief gRPC (gun) 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——CONNECT 握手在工厂内部完成
 * - 连接：Conn（流，Conn.hpp，CONNECT 握手 + 数据透传）
 * - 编解码：Codec.hpp（protobuf varint + gun 帧编解码）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Gun/Codec.hpp>
#include <common/Protocols/Gun/Conn.hpp>
#include <common/Protocols/Gun/Types.hpp>

namespace Preview::Gun
{

    /**
     * @brief 创建客户端流连接并完成 CONNECT 握手
     * @param upstream 上游传输（所有权移交）
     * @param host 目标主机
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, std::string_view host)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream));
        const auto err = co_await c->WriteHandshake(host);
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
     * @brief 接收服务端流连接并完成 CONNECT 握手
     * @param upstream 上游传输（所有权移交）
     * @return 错误码、解析的目标与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream)
        -> net::awaitable<std::tuple<Error, std::string, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(std::move(upstream));
        std::string host;
        const auto err = co_await c->ReadHandshake(host);
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{err, std::move(host), std::move(Conn)};
    }

} // namespace Preview::Gun
