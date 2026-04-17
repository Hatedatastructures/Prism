/**
 * @file shadowsocks.hpp
 * @brief SS2022 Pipeline 处理器声明
 * @details 声明 Shadowsocks 2022 协议的会话处理函数，
 * 负责无正特征的 SS2022 协议检测、密钥验证和数据转发
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
     * @brief SS2022 协议处理函数
     * @details 处理 Shadowsocks 2022 协议会话，包括 AEAD 解密验证、
     * 地址解析和双向隧道转发
     * @param ctx 会话上下文，包含入站传输和配置信息
     * @param data 预读数据，协议检测时读取的初始数据
     * @return net::awaitable<void> 异步操作对象
     */
    auto shadowsocks(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace psm::pipeline
