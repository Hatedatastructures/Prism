/**
 * @file handlers.hpp
 * @brief 协议处理器分发器
 * @details 定义具体协议处理器实现如 Http、SOCKS5、Trojan、VLESS、Unknown 及其全局注册函数。
 * 这些处理器将检测到的协议数据流转发到相应的协议处理流水线。架构说明方面，
 * 处理器类是具体的协议处理器类继承自 handler 基类，实现 process 方法。处理器
 * 注册通过 registry::global 工厂注册所有协议处理器。单例设计，每个协议处理器类
 * 为单例，避免每个连接重复创建。流水线委托，处理逻辑委托给 pipeline 命名空间
 * 的具体处理函数。协议支持包括 Http 支持 Http/1.1，包括 GET、POST、CONNECT
 * 等方法。SOCKS5 支持 SOCKS5 协议标准定义的认证和连接命令。Trojan 支持
 * Trojan over TLS 代理协议。VLESS 支持 VLESS 协议，通过 UUID 认证。
 * Unknown 支持原始 TCP 透传。设计特性包括工厂模式，通过 registry::global
 * 工厂创建处理器实例。单例优化，每个协议处理器类为单例，减少内存分配。
 * 类型安全，使用模板参数和 protocol_type 枚举确保类型正确性。协程支持，
 * 所有 process 方法都是协程，支持异步处理。
 * @note 所有处理器继承自 handler 基类，通过 registry::global 工厂注册。
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
     * @details 实现 Http 协议的处理逻辑，将检测到的 Http 数据流转发到 pipeline::http
     * 处理流水线。该处理器通过 registry::global 工厂注册，在协议检测阶段被调用。
     * 核心职责包括协议标识，通过 type 方法返回 protocol_type::http。名称标识，
     * 通过 name 方法返回 http 用于日志。数据处理，通过 process 方法将 Http 流
     * 转发到 pipeline::http。线程安全性设计方面，无状态设计，处理器实例不持有
     * 任何状态，所有处理逻辑在 pipeline::http 中。单例模式，工厂内部维护单例，
     * 避免多线程创建多个实例。协程安全，process 方法为协程，保证单线程执行。
     * @note 该处理器为单例实例，避免每个连接重复创建。
     * @warning 处理器实例不持有状态，所有处理逻辑委托给 pipeline::http 协程。
     */
    class Http : public handler
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造 Http 协议处理器实例。该构造函数不执行任何初始化操作。
         * @note 处理器应为单例，构造函数仅用于工厂创建。
         */
        Http()= default;

        /**
         * @brief 获取协议类型
         * @details 返回 protocol::protocol_type::http 标识该处理器为 Http 协议处理器。
         * @return protocol::protocol_type::http 协议类型枚举
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::http;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回字符串字面量 http 用于日志和调试。
         * @return http 处理器名称
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "http";
        }

        /**
         * @brief 处理协议数据流
         * @details 将 Http 协议数据流转发到 pipeline::http 处理流水线。该协程负责
         * 将会话上下文和数据传递给流水线。等待流水线处理完成。返回处理结果。
         * @param ctx 会话上下文，包含所有必要的资源和状态
         * @param data 协议数据切片，包含已读取的协议头部数据
         * @throws std::bad_alloc 如果内存分配失败
         * @throws std::runtime_error 如果流水线处理失败
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::http(ctx, data);
        }
    };

    /**
     * @class Socks5
     * @brief SOCKS5 协议处理器
     * @details 实现 SOCKS5 协议的处理逻辑，将检测到的 SOCKS5 数据流转发到
     * pipeline::socks5 处理流水线。该处理器通过 registry::global 工厂注册，
     * 在协议检测阶段被调用。核心职责包括协议标识，通过 type 方法返回
     * protocol_type::socks5。名称标识，通过 name 方法返回 socks5 用于日志。
     * 数据处理，通过 process 方法将 SOCKS5 流转发到 pipeline::socks5。
     * 线程安全性设计方面，无状态设计，处理器实例不持有任何状态，所有处理逻辑
     * 在 pipeline::socks5 中。单例模式，工厂内部维护单例，避免多线程创建多个
     * 实例。协程安全，process 方法为协程，保证单线程执行。
     * @note 该处理器为单例实例，避免每个连接重复创建。
     * @warning 处理器实例不持有状态，所有处理逻辑委托给 pipeline::socks5 协程。
     */
    class Socks5 : public handler
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造 SOCKS5 协议处理器实例。该构造函数不执行任何初始化操作。
         * @note 处理器应为单例，构造函数仅用于工厂创建。
         */
        Socks5() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 protocol::protocol_type::socks5 标识该处理器为 SOCKS5 协议处理器。
         * @return protocol::protocol_type::socks5 协议类型枚举
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::socks5;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回字符串字面量 socks5 用于日志和调试。
         * @return socks5 处理器名称
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "socks5";
        }

        /**
         * @brief 处理协议数据流
         * @details 将 SOCKS5 协议数据流转发到 pipeline::socks5 处理流水线。该协程负责
         * 将会话上下文和数据传递给流水线。等待流水线处理完成。返回处理结果。
         * @param ctx 会话上下文，包含所有必要的资源和状态
         * @param data 协议数据切片，包含已读取的协议头部数据
         * @throws std::bad_alloc 如果内存分配失败
         * @throws std::runtime_error 如果流水线处理失败
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::socks5(ctx, data);
        }
    };

    /**
     * @class Trojan
     * @brief Trojan over TLS 协议处理器
     * @details 实现 Trojan 协议的处理逻辑，将检测到的 TLS 数据流转发到 pipeline::trojan
     * 处理流水线。该处理器通过 registry::global 工厂注册，在协议检测阶段被调用。
     * 核心职责包括协议标识，通过 type 方法返回 protocol_type::trojan。名称标识，
     * 通过 name 方法返回 trojan 用于日志。数据处理，通过 process 方法将 TLS 流
     * 转发到 pipeline::trojan，内部完成 TLS 握手和 Trojan 协议处理。
     * 线程安全性设计方面，无状态设计，处理器实例不持有任何状态，所有处理逻辑
     * 在 pipeline::trojan 中。单例模式，工厂内部维护单例，避免多线程创建多个
     * 实例。协程安全，process 方法为协程，保证单线程执行。
     * @note 该处理器为单例实例，避免每个连接重复创建。
     * @warning 处理器实例不持有状态，所有处理逻辑委托给 pipeline::trojan 协程。
     */
    class Trojan : public handler
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造 Trojan 协议处理器实例。该构造函数不执行任何初始化操作。
         * @note 处理器应为单例，构造函数仅用于工厂创建。
         */
        Trojan() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 protocol::protocol_type::trojan 标识该处理器为 Trojan 协议处理器。
         * @return protocol::protocol_type::trojan 协议类型枚举
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::trojan;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回字符串字面量 trojan 用于日志和调试。
         * @return trojan 处理器名称
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "trojan";
        }

        /**
         * @brief 处理协议数据流
         * @details 将 Trojan 协议数据流转发到 pipeline::trojan 处理流水线。该协程负责
         * 将会话上下文和数据传递给流水线。等待流水线处理完成。返回处理结果。
         * @param ctx 会话上下文，包含所有必要的资源和状态
         * @param data 协议数据切片，包含已读取的 TLS ClientHello 数据
         * @throws std::bad_alloc 如果内存分配失败
         * @throws std::runtime_error 如果流水线处理失败
         */
        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::trojan(ctx, data);
        }
    };

    /**
     * @class Vless
     * @brief VLESS 协议处理器
     * @details 实现 VLESS 协议的处理逻辑，将检测到的 VLESS 数据流转发到
     * pipeline::vless 处理流水线。VLESS 协议运行在 TLS 内层，通过 UUID
     * 进行用户认证。该处理器为无状态单例。
     */
    class Vless : public handler
    {
    public:
        Vless() = default;

        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::vless;
        }

        [[nodiscard]] std::string_view name() const override
        {
            return "vless";
        }

        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::vless(ctx, data);
        }
    };

    /**
     * @class Shadowsocks
     * @brief SS2022 (Shadowsocks 2022) 协议处理器
     * @details 实现 SS2022 协议的处理逻辑，将检测到的 SS2022 数据流转发到
     * pipeline::shadowsocks 处理流水线。SS2022 使用 BLAKE3 密钥派生和 AES-GCM AEAD
     * 加密，运行在 TLS 内层。该处理器为无状态单例。
     */
    class Shadowsocks : public handler
    {
    public:
        Shadowsocks() = default;

        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::shadowsocks;
        }

        [[nodiscard]] std::string_view name() const override
        {
            return "shadowsocks";
        }

        auto process(session_context &ctx, const std::span<const std::byte> data)
            -> net::awaitable<void> override
        {
            co_await pipeline::shadowsocks(ctx, data);
        }
    };

    /**
     * @class Unknown
     * @brief Unknown 协议处理器
     * @details 实现未知协议的处理逻辑，执行原始 TCP 双向透传。该处理器作为默认
     * 回退处理器，当协议检测无法识别协议类型时使用。核心职责包括协议标识，
     * 通过 type 方法返回 protocol_type::unknown。名称标识，通过 name 方法返回
     * unknown 用于日志。数据处理，通过 process 方法执行原始隧道转发。线程安全
     * 性设计方面，无状态设计，处理器实例不持有任何状态。单例模式，工厂内部维护
     * 单例，避免多线程创建多个实例。协程安全，process 方法为协程，保证单线程执行。
     * @note 该处理器为单例实例，作为默认回退处理器使用。
     * @warning 该处理器要求 ctx.outbound 已建立，否则无法执行透传。
     */
    class Unknown : public handler
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造 Unknown 协议处理器实例。该构造函数不执行任何初始化操作。
         * @note 处理器应为单例，构造函数仅用于工厂创建。
         */
        Unknown() = default;

        /**
         * @brief 获取协议类型
         * @details 返回 protocol::protocol_type::unknown 标识该处理器为 Unknown 协议处理器。
         * @return protocol::protocol_type::unknown 协议类型枚举
         */
        [[nodiscard]] protocol::protocol_type type() const override
        {
            return protocol::protocol_type::unknown;
        }

        /**
         * @brief 获取处理器名称
         * @details 返回字符串字面量 unknown 用于日志和调试。
         * @return unknown 处理器名称
         */
        [[nodiscard]] std::string_view name() const override
        {
            return "unknown";
        }

        /**
         * @brief 处理协议数据流
         * @details 执行原始 TCP 双向透传。该协程检查入站和出站传输层是否存在，
         * 然后调用 primitives::tunnel 建立全双工隧道。
         * @param ctx 会话上下文，包含入站和出站传输层
         * @throws std::bad_alloc 如果内存分配失败
         * @note 该方法要求 ctx.inbound 和 ctx.outbound 都有效。
         * @warning 如果入站或出站传输层缺失，协程会提前返回。
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
    };

    /**
     * @brief 注册所有协议处理器到全局工厂
     * @details 将 Http、SOCKS5、Trojan、VLESS、Unknown 协议处理器注册到全局处理器工厂
     * registry::global。该函数应在程序初始化阶段调用，确保所有协议处理器在
     * 检测阶段可用。注册流程为获取全局工厂单例引用。为每种协议类型注册对应的
     * 处理器类模板。工厂内部将创建处理器单例实例。注册协议包括 Http 协议，
     * 注册 Http 到 protocol_type::http。SOCKS5 协议，注册 Socks5
     * 到 protocol_type::socks5。Trojan 协议，注册 Trojan 到 protocol_type::trojan。
     * VLESS 协议，注册 Vless 到 protocol_type::vless。
     * Unknown 协议，注册 Unknown 到 protocol_type::unknown。
     * @note 该函数是幂等的，多次调用不会重复注册相同处理器。
     * @warning 必须在所有工作线程启动前调用，避免线程竞争。
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::runtime_error 如果工厂注册失败
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
