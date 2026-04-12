/**
 * @file shadowsocks.hpp
 * @brief SS2022 Pipeline 处理器声明
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
     * @param ctx 会话上下文
     * @param data 预读数据
     */
    auto shadowsocks(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>;

} // namespace psm::pipeline
