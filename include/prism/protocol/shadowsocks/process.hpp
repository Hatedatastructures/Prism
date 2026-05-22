/**
 * @file process.hpp
 * @brief Shadowsocks 协议处理入口声明
 * @details 声明 SS2022 协议的完整处理流程：握手 → 转发。
 */
#pragma once

#include <span>

#include <boost/asio.hpp>

#include <prism/context/context.hpp>

namespace psm::protocol::shadowsocks
{
    namespace net = boost::asio;

    /**
     * @brief Shadowsocks 协议完整处理流程
     * @details 协调 relay 握手、目标解析和隧道转发。
     * @param ctx 会话上下文
     * @param data 预读数据
     */
    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;
} // namespace psm::protocol::shadowsocks
