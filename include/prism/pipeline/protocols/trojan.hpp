/**
 * @file trojan.hpp
 * @brief Trojan 协议处理管道
 * @details 声明 Trojan 代理协议的会话处理函数。TLS 握手在 Session 层完成，
 * 本模块负责 Trojan 协议握手、凭据验证、命令分发和多路复用引导。
 * 支持 CONNECT（TCP 隧道）、UDP_ASSOCIATE（UDP over TLS）和 mux 多路复用。
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
     * @brief Trojan 协议处理函数
     * @param ctx 会话上下文，包含入站传输和配置信息
     * @param data 预读数据，Session 层 TLS 剥离后的内层协议数据
     * @return 异步操作对象，处理完成后返回
     * @details 处理 Trojan 协议流量（TLS 已在 Session 层剥离）。
     * 处理流程包括 Trojan 握手解析凭据和目标地址、
     * 账户验证、命令分发（CONNECT/UDP_ASSOCIATE/mux）。
     * @note 该函数由协议检测器直接调用。
     */
    auto trojan(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace psm::pipeline
