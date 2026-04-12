/**
 * @file vless.hpp
 * @brief VLESS 协议处理管道
 * @details 声明 VLESS 代理协议的会话处理函数。TLS 握手在 Session 层完成，
 * 本模块负责 VLESS 协议握手、UUID 验证、命令分发和多路复用引导。
 */
#pragma once

#include <cstddef>
#include <span>
#include <boost/asio.hpp>
#include <prism/agent/context.hpp>
#include <prism/pipeline/primitives.hpp>

namespace psm::pipeline
{
    using psm::agent::session_context;
    namespace net = boost::asio;

    /**
     * @brief VLESS 协议处理函数
     * @param ctx 会话上下文
     * @param data 预读数据，Session 层 TLS 剥离后的内层协议数据
     * @return 异步操作对象
     */
    auto vless(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace psm::pipeline
