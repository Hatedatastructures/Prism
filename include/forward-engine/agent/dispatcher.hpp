#pragma once

/**
 * @file dispatcher.hpp
 * @brief 协议处理器分发器
 * @details 定义具体协议处理器实现（`HTTP`、`SOCKS5`、`TLS`）及其全局注册函数。
 * 这些处理器将检测到的协议数据流转发到相应的协议处理流水线。
 *
 * @note 所有处理器继承自 `handler` 基类，通过 `registry::global()` 工厂注册。
 * @warning 处理器应为单例实例，避免每个连接重复创建。
 */

#include <boost/asio.hpp>
#include <forward-engine/agent/handler.hpp>
#include <forward-engine/agent/detection.hpp>

namespace ngx::agent
{
    /**
     * @class http_handler
     * @brief HTTP 协议处理器
     * @details 实现 `HTTP` 协议的处理逻辑，将检测到的 `HTTP` 数据流转发到 `pipeline::http` 处理流水线。
     * 该处理器通过 `registry::global()` 工厂注册，在协议检测阶段被调用。
     *
     * @note 该处理器为单例实例，避免每个连接重复创建。
     * @warning 处理器实例不持有状态，所有处理逻辑委托给 `pipeline::http` 协程。
     *
     * ```
     * // 使用示例：通过工厂获取 HTTP 处理器
     * auto& factory = registry::global();
     * auto handler = factory.create(protocol::protocol_type::http);
     * // 处理连接数据
     * co_await handler->process(inbound, distributor, ctx, data);
     * ```
     */
    class http_handler : public handler
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造 `HTTP` 协议处理器实例。该构造函数不执行任何初始化操作。
         * @note 处理器应为单例，构造函数仅用于工厂创建。
         */
        http_handler()
        {
        }

        /**
         * @brief 获取协议类型
         * @details 返回 `protocol::protocol_type::http` 标识该处理器为 `HTTP` 协议处理器。
         * @return `protocol::protocol_type::http` 协议类型枚举
         */
        protocol::protocol_type type() const override
        {
            return protocol::protocol_type::http;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回字符串字面量 "http" 用于日志和调试。
         * @return "http" 处理器名称
         */
        std::string_view name() const override
        {
            return "http";
        }

        /**
         * @brief 处理协议数据流
         * @details 将 `HTTP` 协议数据流转发到 `pipeline::http` 处理流水线。该协程负责：
         * - 将入站传输对象、分发器、上下文和数据传递给流水线；
         * - 等待流水线处理完成；
         * - 返回处理结果。
         * @param inbound 入站传输对象指针，所有权转移给流水线
         * @param distributor 分发器共享指针，用于路由和连接管理
         * @param ctx 处理器上下文，包含 `SSL` 上下文等配置
         * @param data 协议数据切片，包含已读取的协议头部数据
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::runtime_error` 如果流水线处理失败
         */
        auto process(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
                     const handler_context &ctx, std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::http(std::move(inbound), distributor, ctx, data);
        }
    };

    /**
     * @class socks5_handler
     * @brief SOCKS5 协议处理器
     * @details 实现 `SOCKS5` 协议的处理逻辑，将检测到的 `SOCKS5` 数据流转发到 `pipeline::socks5` 处理流水线。
     * 该处理器通过 `registry::global()` 工厂注册，在协议检测阶段被调用。
     *
     * @note 该处理器为单例实例，避免每个连接重复创建。
     * @warning 处理器实例不持有状态，所有处理逻辑委托给 `pipeline::socks5` 协程。
     *
     * ```
     * // 使用示例：通过工厂获取 SOCKS5 处理器
     * auto& factory = registry::global();
     * auto handler = factory.create(protocol::protocol_type::socks5);
     * // 处理连接数据
     * co_await handler->process(inbound, distributor, ctx, data);
     * ```
     */
    class socks5_handler : public handler
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造 `SOCKS5` 协议处理器实例。该构造函数不执行任何初始化操作。
         * @note 处理器应为单例，构造函数仅用于工厂创建。
         */
        socks5_handler() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 `protocol::protocol_type::socks5` 标识该处理器为 `SOCKS5` 协议处理器。
         * @return `protocol::protocol_type::socks5` 协议类型枚举
         */
        protocol::protocol_type type() const override
        {
            return protocol::protocol_type::socks5;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回字符串字面量 "socks5" 用于日志和调试。
         * @return "socks5" 处理器名称
         */
        std::string_view name() const override
        {
            return "socks5";
        }

        /**
         * @brief 处理协议数据流
         * @details 将 `SOCKS5` 协议数据流转发到 `pipeline::socks5` 处理流水线。该协程负责：
         * @details - 将入站传输对象、分发器、上下文和数据传递给流水线；
         * @details - 等待流水线处理完成；
         * @details - 返回处理结果。
         * @param inbound 入站传输对象指针，所有权转移给流水线
         * @param distributor 分发器共享指针，用于路由和连接管理
         * @param ctx 处理器上下文，包含 `SSL` 上下文等配置
         * @param data 协议数据切片，包含已读取的协议头部数据
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::runtime_error` 如果流水线处理失败
         */
        auto process(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
                     const handler_context &ctx, std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::socks5(std::move(inbound), distributor, ctx, data);
        }
    };

    /**
     * @class tls_handler
     * @brief TLS 协议处理器
     * @details 实现 `TLS` 协议的处理逻辑，将检测到的 `TLS` 数据流转发到 `pipeline::tls` 处理流水线。
     * 该处理器通过 `registry::global()` 工厂注册，在协议检测阶段被调用。
     *
     * @note 该处理器为单例实例，避免每个连接重复创建。
     * @warning 处理器实例不持有状态，所有处理逻辑委托给 `pipeline::tls` 协程。
     *
     * ```
     * // 使用示例：通过工厂获取 TLS 处理器
     * auto& factory = registry::global();
     * auto handler = factory.create(protocol::protocol_type::tls);
     * // 处理连接数据
     * co_await handler->process(inbound, distributor, ctx, data);
     * ```
     */
    class tls_handler : public handler
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造 `TLS` 协议处理器实例。该构造函数不执行任何初始化操作。
         * @note 处理器应为单例，构造函数仅用于工厂创建。
         */
        tls_handler() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 `protocol::protocol_type::tls` 标识该处理器为 `TLS` 协议处理器。
         * @return `protocol::protocol_type::tls` 协议类型枚举
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::tls;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回字符串字面量 "tls" 用于日志和调试。
         * @return "tls" 处理器名称
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "tls";
        }

        /**
         * @brief 处理协议数据流
         * @details 将 `TLS` 协议数据流转发到 `pipeline::tls` 处理流水线。该协程负责：
         * @details - 将入站传输对象、分发器、`SSL` 上下文、处理器上下文和数据传递给流水线；
         * @details - 等待流水线处理完成；
         * @details - 返回处理结果。
         * @param inbound 入站传输对象指针，所有权转移给流水线
         * @param distributor 分发器共享指针，用于路由和连接管理
         * @param ctx 处理器上下文，包含 `SSL` 上下文等配置
         * @param data 协议数据切片，包含已读取的协议头部数据
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::runtime_error` 如果流水线处理失败
         */
        auto process(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
                     const handler_context &ctx, std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::tls(std::move(inbound), distributor, ctx.ssl_ctx, ctx, data);
        }
    };

    /**
     * @brief 注册所有协议处理器到全局工厂
     * @details 将 `HTTP`、`SOCKS5`、`TLS` 协议处理器注册到全局处理器工厂 `registry::global()`。
     * 该函数应在程序初始化阶段调用，确保所有协议处理器在检测阶段可用。
     *
     * 注册流程：
     * @details - 获取全局工厂单例引用；
     * @details - 为每种协议类型注册对应的处理器类模板；
     * @details - 工厂内部将创建处理器单例实例。
     *
     * @note 该函数是幂等的：多次调用不会重复注册相同处理器。
     * @warning 必须在所有工作线程启动前调用，避免线程竞争。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果工厂注册失败
     *
     * ```
     * // 使用示例：在程序初始化时注册处理器
     * ngx::agent::register_handlers();
     * // 之后即可通过工厂创建处理器
     * auto handler = registry::global().create(protocol::protocol_type::http);
     * ```
     */
    inline void register_handlers()
    {
        auto &factory = registry::global();
        // http
        factory.register_handler<http_handler>(protocol::protocol_type::http);
        // socks5
        factory.register_handler<socks5_handler>(protocol::protocol_type::socks5);
        // tls
        factory.register_handler<tls_handler>(protocol::protocol_type::tls);
    }

} // namespace ngx::agent
