/**
 * @file handlers.hpp
 * @brief 协议处理器分发器
 * @details 定义具体协议处理器实现，包括 Http、SOCKS5、
 * Trojan、VLESS、Shadowsocks 及 Unknown，及其全局注册
 * 函数。这些处理器将检测到的协议数据流转发到相应的协议
 * 处理流水线。
 * @note 所有处理器继承自 handler 基类，通过
 * registry::global 工厂注册。
 * @warning 处理器应为单例实例，避免每个连接重复创建。
 */

#pragma once

#include <prism/agent/dispatch/handler.hpp>
#include <prism/pipeline/protocols.hpp>
#include <prism/pipeline/primitives.hpp>

namespace psm::agent::dispatch
{
    /**
     * @class Http
     * @brief Http 协议处理器
     * @details 将检测到的 Http 数据流转发到 pipeline::http
     * 处理流水线。该处理器为无状态单例。
     * @note 该处理器不持有任何传输层或资源的长期引用
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::system_error 如果底层系统调用失败
     */
    class Http : public handler
    {
    public:
        Http() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 Http 协议类型枚举值。
         * @return protocol::protocol_type::http
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::http;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回 Http 协议的可读名称字符串。
         * @return "http"
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "http";
        }

        /**
         * @brief 处理 Http 协议数据流
         * @details 将 Http 数据流委托给 pipeline::http 处理。
         * @param ctx 会话上下文
         * @param data 协议数据切片
         * @return 协程等待对象
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::http(ctx, data);
        }
    }; // class Http

    /**
     * @class Socks5
     * @brief SOCKS5 协议处理器
     * @details 将检测到的 SOCKS5 数据流转发到
     * pipeline::socks5 处理流水线。该处理器为无状态单例。
     * @note 该处理器不持有任何传输层或资源的长期引用
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::system_error 如果底层系统调用失败
     */
    class Socks5 : public handler
    {
    public:
        Socks5() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 SOCKS5 协议类型枚举值。
         * @return protocol::protocol_type::socks5
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::socks5;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回 SOCKS5 协议的可读名称字符串。
         * @return "socks5"
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "socks5";
        }

        /**
         * @brief 处理 SOCKS5 协议数据流
         * @details 将 SOCKS5 数据流委托给 pipeline::socks5 处理。
         * @param ctx 会话上下文
         * @param data 协议数据切片
         * @return 协程等待对象
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::socks5(ctx, data);
        }
    }; // class Socks5

    /**
     * @class Trojan
     * @brief Trojan over TLS 协议处理器
     * @details 将检测到的 Trojan 数据流转发到
     * pipeline::trojan 处理流水线。该处理器为无状态单例。
     * @note 该处理器不持有任何传输层或资源的长期引用
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::system_error 如果底层系统调用失败
     */
    class Trojan : public handler
    {
    public:
        Trojan() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 Trojan 协议类型枚举值。
         * @return protocol::protocol_type::trojan
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::trojan;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回 Trojan 协议的可读名称字符串。
         * @return "trojan"
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "trojan";
        }

        /**
         * @brief 处理 Trojan 协议数据流
         * @details 将 Trojan 数据流委托给 pipeline::trojan 处理。
         * @param ctx 会话上下文
         * @param data 协议数据切片
         * @return 协程等待对象
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::trojan(ctx, data);
        }
    }; // class Trojan

    /**
     * @class Vless
     * @brief VLESS 协议处理器
     * @details 将检测到的 VLESS 数据流转发到
     * pipeline::vless 处理流水线。VLESS 协议运行在
     * TLS 内层，通过 UUID 进行用户认证。该处理器为
     * 无状态单例。
     * @note 该处理器不持有任何传输层或资源的长期引用
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::system_error 如果底层系统调用失败
     */
    class Vless : public handler
    {
    public:
        Vless() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 VLESS 协议类型枚举值。
         * @return protocol::protocol_type::vless
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::vless;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回 VLESS 协议的可读名称字符串。
         * @return "vless"
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "vless";
        }

        /**
         * @brief 处理 VLESS 协议数据流
         * @details 将 VLESS 数据流委托给 pipeline::vless 处理。
         * @param ctx 会话上下文
         * @param data 协议数据切片
         * @return 协程等待对象
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::vless(ctx, data);
        }
    }; // class Vless

    /**
     * @class Shadowsocks
     * @brief SS2022 协议处理器
     * @details 将检测到的 SS2022 数据流转发到
     * pipeline::shadowsocks 处理流水线。SS2022 使用
     * BLAKE3 密钥派生和 AES-GCM AEAD 加密。该处理器
     * 为无状态单例。
     * @note 该处理器不持有任何传输层或资源的长期引用
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::system_error 如果底层系统调用失败
     */
    class Shadowsocks : public handler
    {
    public:
        Shadowsocks() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 Shadowsocks 协议类型枚举值。
         * @return protocol::protocol_type::shadowsocks
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::shadowsocks;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回 Shadowsocks 协议的可读名称字符串。
         * @return "shadowsocks"
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "shadowsocks";
        }

        /**
         * @brief 处理 SS2022 协议数据流
         * @details 将 SS2022 数据流委托给 pipeline::shadowsocks 处理。
         * @param ctx 会话上下文
         * @param data 协议数据切片
         * @return 协程等待对象
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::shadowsocks(ctx, data);
        }
    }; // class Shadowsocks

    /**
     * @class Unknown
     * @brief Unknown 协议处理器
     * @details 执行原始 TCP 双向透传。作为默认回退处理器，
     * 当协议检测无法识别协议类型时使用。
     * @note 该处理器要求 ctx.outbound 已建立
     * @warning 如果入站或出站传输层缺失，协程会提前返回
     */
    class Unknown : public handler
    {
    public:
        Unknown() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 Unknown 协议类型枚举值。
         * @return protocol::protocol_type::unknown
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::unknown;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回 Unknown 协议的可读名称字符串。
         * @return "unknown"
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "unknown";
        }

        /**
         * @brief 处理未知协议数据流
         * @details 执行原始 TCP 双向透传，数据参数被忽略。
         * @param ctx 会话上下文，包含入站和出站传输层
         * @return 协程等待对象
         * @note 该方法要求 ctx.inbound 和 ctx.outbound 都有效
         * @warning 如果入站或出站传输层缺失，协程会提前返回
         */
        auto process(session_context &ctx, [[maybe_unused]] std::span<const std::byte> /*data*/)
            -> net::awaitable<void> override
        {

            if (!ctx.inbound || !ctx.outbound)
            {
                trace::warn("[Unknown] splice aborted: inbound or outbound transmission missing.");
                co_return;
            }

            trace::debug("[Unknown] Starting full-duplex splice.");
            co_await pipeline::primitives::tunnel(std::move(ctx.inbound), std::move(ctx.outbound), ctx);
            trace::debug("[Unknown] Splice finished.");
        }
    }; // class Unknown

    /**
     * @brief 注册所有协议处理器到全局工厂
     * @details 将 Http、SOCKS5、Trojan、VLESS、Shadowsocks、
     * Unknown 协议处理器注册到全局处理器工厂
     * registry::global。该函数应在程序初始化阶段调用。
     * @note 该函数是幂等的，多次调用不会重复注册相同处理器
     * @warning 必须在所有工作线程启动前调用，避免线程竞争
     */
    inline void register_handlers()
    {
        auto &factory = registry::global();
        factory.register_handler<Http>(protocol::protocol_type::http);
        factory.register_handler<Socks5>(protocol::protocol_type::socks5);
        factory.register_handler<Trojan>(protocol::protocol_type::trojan);
        factory.register_handler<Vless>(protocol::protocol_type::vless);
        factory.register_handler<Shadowsocks>(protocol::protocol_type::shadowsocks);
        factory.register_handler<Unknown>(protocol::protocol_type::unknown);
    }

} // namespace psm::agent::dispatch
