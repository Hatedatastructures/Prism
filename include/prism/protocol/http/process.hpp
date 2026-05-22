/**
 * @file process.hpp
 * @brief HTTP 协议处理入口声明
 * @details 声明 HTTP 协议的完整处理流程：握手认证 → 目标解析 → CONNECT/普通转发。
 */
#pragma once

#include <span>

#include <boost/asio.hpp>

#include <prism/context/context.hpp>

namespace psm::protocol::http
{
    namespace net = boost::asio;

    /**
     * @brief HTTP 协议完整处理流程
     * @details 协调 relay 握手、目标解析和隧道转发，处理 CONNECT 和普通 HTTP 方法。
     * @param ctx 会话上下文
     * @param data 预读数据
     */
    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;
} // namespace psm::protocol::http
