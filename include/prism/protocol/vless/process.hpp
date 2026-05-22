/**
 * @file process.hpp
 * @brief VLESS 协议处理入口声明
 * @details 声明 VLESS 协议的完整处理流程：握手认证 → 目标解析 → 转发。
 * 这是 VLESS 协议的业务逻辑入口，协调 relay 握手和 connect 模块完成数据转发。
 */
#pragma once

#include <span>

#include <boost/asio.hpp>

#include <prism/context/context.hpp>

namespace psm::protocol::vless
{
    namespace net = boost::asio;

    /**
     * @brief VLESS 协议完整处理流程
     * @details 协调 relay 握手、目标解析和隧道转发，处理 TCP/UDP/MUX 三种命令。
     * @param ctx 会话上下文
     * @param data 预读数据
     */
    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;
} // namespace psm::protocol::vless
