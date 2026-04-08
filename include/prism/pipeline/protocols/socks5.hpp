/**
 * @file socks5.hpp
 * @brief SOCKS5 协议处理管道
 * @details 声明 SOCKS5 代理协议的会话处理函数，包括握手协商、
 * 请求解析、命令分发和双向隧道转发。支持 CONNECT 和 UDP_ASSOCIATE
 * 命令。
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
     * @brief SOCKS5 协议处理函数
     * @param ctx 会话上下文，包含入站传输和配置信息
     * @param data 预读数据，协议检测时读取的初始数据
     * @return 异步操作对象，处理完成后返回
     * @details 处理 SOCKS5 握手、请求和转发。支持 CONNECT（TCP 隧道）
     * 和 UDP_ASSOCIATE（UDP 中继）命令，不支持 BIND 命令。
     * @warning SOCKS5 协议要求预读数据为空，否则握手可能失败。
     */
    auto socks5(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace psm::pipeline
