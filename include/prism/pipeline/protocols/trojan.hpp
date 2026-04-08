/**
 * @file trojan.hpp
 * @brief Trojan over TLS 协议处理管道
 * @details 声明 Trojan over TLS 代理协议的会话处理函数，包括 TLS 握手、
 * Trojan 协议握手、凭据验证、命令分发和多路复用引导。支持 CONNECT
 * （TCP 隧道）、UDP_ASSOCIATE（UDP over TLS）和 mux 多路复用。
 */
#pragma once

#include <cstddef>
#include <span>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <prism/agent/context.hpp>
#include <prism/pipeline/primitives.hpp>

namespace psm::pipeline
{
    using psm::agent::session_context;
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @brief Trojan over TLS 协议处理函数
     * @param ctx 会话上下文，包含入站传输和配置信息
     * @param data 预读数据，协议检测时读取的 TLS ClientHello 数据
     * @return 异步操作对象，处理完成后返回
     * @details 处理 Trojan over TLS 流量，内部完成 TLS 握手。
     * 处理流程包括 TLS 握手、Trojan 握手解析凭据和目标地址、
     * 账户验证、命令分发（CONNECT/UDP_ASSOCIATE/mux）。
     * @note 该函数由协议检测器直接调用。
     */
    auto trojan(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace psm::pipeline
