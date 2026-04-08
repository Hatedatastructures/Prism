/**
 * @file http.hpp
 * @brief HTTP 协议处理管道
 * @details 声明 HTTP 代理协议的会话处理函数，包括请求解析、代理认证、
 * 上游连接建立以及双向隧道转发。支持 CONNECT 方法（HTTPS 隧道）
 * 和普通 HTTP 请求转发。
 */
#pragma once

#include <cstddef>
#include <span>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <prism/agent/context.hpp>
#include <prism/pipeline/primitives.hpp>

namespace psm::pipeline
{
    using psm::agent::session_context;
    namespace net = boost::asio;
    namespace beast = boost::beast;

    /**
     * @brief HTTP 协议处理函数
     * @param ctx 会话上下文，包含入站传输和配置信息
     * @param data 预读数据，协议检测时读取的初始数据
     * @return 异步操作对象，处理完成后返回
     * @details 解析 HTTP 请求，执行代理认证（若已配置账户目录），
     * 连接上游，并建立隧道。对于 CONNECT 方法，向客户端发送
     * 200 Connection Established 响应后建立原始隧道进行透明转发。
     * 对于普通请求，将请求序列化后转发到上游，然后建立双向隧道。
     * @note 支持 HTTP/1.1，自动处理 chunked 编码和连接复用。
     * @warning 如果请求解析失败或连接建立失败，会静默关闭连接。
     */
    auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace psm::pipeline
