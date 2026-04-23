/**
 * @file handler_table.hpp
 * @brief 协议处理函数表
 * @details 使用编译期数组替代虚函数 + 工厂模式，实现协议分发。
 * 每个 handler 函数直接调用对应的 pipeline 函数，无额外包装层。
 * 零虚函数、零动态分配、编译时可内联。
 */
#pragma once

#include <cstddef>
#include <span>
#include <boost/asio.hpp>

#include <prism/agent/context.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/pipeline/protocols.hpp>

namespace psm::agent::dispatch
{
    namespace net = boost::asio;

    /**
     * @brief 协议处理函数类型
     * @param ctx 会话上下文
     * @param data 预读数据
     * @return 协程
     */
    using handler_func = net::awaitable<void>(session_context &, std::span<const std::byte>);

    /**
     * @brief Unknown 协议处理器 — 原始 TCP 透传
     */
    inline auto handle_unknown(session_context &ctx, std::span<const std::byte> /*data*/)
        -> net::awaitable<void>
    {
        if (!ctx.inbound || !ctx.outbound)
        {
            co_return;
        }
        co_await pipeline::primitives::tunnel(std::move(ctx.inbound), std::move(ctx.outbound), ctx);
    }

    /**
     * @brief 协议处理函数表
     * @details 数组索引对应 protocol_type 枚举值。
     * 编译期常量，无运行时初始化开销。
     */
    inline constexpr std::array<handler_func *, static_cast<std::size_t>(protocol::protocol_type::tls) + 1>
        handler_table{
            /* unknown     */ handle_unknown,
            /* http        */ pipeline::http,
            /* socks5      */ pipeline::socks5,
            /* trojan      */ pipeline::trojan,
            /* vless       */ pipeline::vless,
            /* shadowsocks */ pipeline::shadowsocks,
            /* tls         */ handle_unknown, // TLS 不应直接到达此表，由 stage chain 处理
        };

    /**
     * @brief 分发到协议处理器
     * @param ctx 会话上下文
     * @param type 协议类型
     * @param data 预读数据
     * @return 协程
     */
    inline auto dispatch(session_context &ctx, protocol::protocol_type type, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        auto idx = static_cast<std::size_t>(type);
        if (idx < handler_table.size() && handler_table[idx])
        {
            co_await handler_table[idx](ctx, data);
        }
        else
        {
            // Fallback to unknown
            co_await handler_table[static_cast<std::size_t>(protocol::protocol_type::unknown)](ctx, data);
        }
    }
} // namespace psm::agent::dispatch
