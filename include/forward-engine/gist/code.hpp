/**
 * @file code.hpp
 * @brief 全局错误码枚举定义
 * @details 定义了 ForwardEngine 系统通用的错误码枚举及相关基础辅助函数。该错误码系统是项目异常处理的基石，遵循"热路径无异常"原则：网络 `I/O`、协议解析、数据转发等热路径严禁抛异常，必须使用错误码返回值进行流控。
 *
 * 典型应用场景：
 * @details - 网络 I/O 操作：`async_read`/`async_write` 异步操作返回错误码而非异常；
 * @details - 协议解析：`HTTP`/`SOCKS5`/`Trojan` 协议解析失败返回具体错误码；
 * @details - 路由转发：转发失败时返回上游不可达、连接拒绝等网络层错误；
 * @details - 配置验证：启动阶段配置解析失败使用异常，运行时配置验证使用错误码。
 *
 * 错误码映射机制：
 * @details - `std::error_code` 兼容：通过 `compatible.hpp` 实现 `std::is_error_code_enum` 特化和 `make_error_code()` 转换；
 * @details - `Boost.System` 兼容：与 `boost::system::error_code` 无缝互操作；
 * @details - 分类映射：通过 `abnormal` 模块异常类映射到 `network`/`security`/`protocol` 分类，输出格式为 `[Category:Value] Description`。
 *
 * @note 异常仅允许用于启动阶段（例如配置加载失败）或致命错误（例如内存耗尽）。
 * @warning 错误码描述函数 `describe()` 返回静态字面量，保证零分配，可用于热路径日志。
 */
#pragma once

#include <string_view>

/**
 * @namespace ngx::gist
 * @brief 基础设置与标准类型（Groundwork & Infrastructure for Standard Types）
 * @details 定义了项目通用的基础类型、错误码枚举 (`Error Code`) 以及跨平台兼容性宏。该命名空间是整个项目的"基石"模块，不依赖其他高级模块，为上层组件提供稳定的基础设施支持。
 *
 * 核心功能：
 * @details - 错误码系统：轻量级错误表示，支持 `std::error_code` 和 `boost::system::error_code` 双向兼容；
 * @details - 类型别名：平台无关的类型定义，消除系统调用和第三方库的类型差异；
 * @details - 编译时检查：静态断言和概念约束，确保类型安全和接口合规；
 * @details - 工具函数：零分配的基础工具，包括错误码描述、成功/失败判断等。
 *
 * @note 该命名空间的内容应保持最小化，避免功能膨胀。
 * @warning 修改基础类型可能破坏整个项目的 `ABI` 兼容性，需进行充分测试。
 *
 * ```
 * // 使用示例：错误码处理
 * namespace gist = ngx::gist;
 * auto ec = gist::code::success;
 * if (gist::failed(ec))
 * {
 *     auto msg = gist::describe(ec);  // 零分配描述
 *     // 处理错误...
 * }
 * ```
 */
namespace ngx::gist
{
    /**
     * @enum code
     * @brief ForwardEngine 全局错误码
     * @note 枚举值 `_count` 仅用于内部统计，不应用于实际错误处理。
     * @warning 错误码比较应使用 `==` 运算符，不要依赖具体的整数值。
     * @throws 无异常（枚举类型本身不抛出异常）
     * @details 表示系统运行时可能出现的所有错误情况。该枚举是错误处理系统的核心，遵循"热路径无异常"设计原则。
     *
     * 设计特性：
     * @details - 轻量级：`4` 字节枚举值，零动态分配，适合值语义传递；
     * @details - 分类清晰：按错误领域分组（网络、安全、协议、系统、`TLS`、`SOCKS5` 等）；
     * @details - 可序列化：可安全转换为整数用于日志或网络传输；
     * @details - `constexpr` 友好：所有枚举值可在编译时使用。
     *
     * 使用原则：
     * @details - 热路径：网络 `I/O`、协议解析、数据转发等热路径必须使用错误码，严禁抛异常；
     * @details - 冷路径：启动阶段配置加载失败或内存耗尽等致命错误可使用异常；
     * @details - 错误传播：通过返回值传播错误，避免全局错误状态。
     *
     * ```
     * // 使用示例：定义函数返回错误码
     * ngx::gist::code my_function()
     * {
     *     if (some_condition)
     *     {
     *         return ngx::gist::code::success;
     *     } else
     *     {
     *         return ngx::gist::code::io_error;
     *     }
     * }
     * // 使用示例：模式匹配处理
     * switch (error_code)
     * {
     *     case ngx::gist::code::success:
     *         // 处理成功
     *         break;
     *     case ngx::gist::code::connection_refused:
     *         // 处理连接拒绝
     *         break;
     *     default:
     *         // 处理其他错误
     *         break;
     * }
     * ```
     */
    enum class code : int
    {
        /**
         * @brief 成功
         */
        success = 0,
        /**
         * @brief 未分类的一般错误
         */
        generic_error = 1,
        /**
         * @brief 解析失败
         * @details 格式不合法、字段缺失等情况。
         */
        parse_error = 2,
        /**
         * @brief 输入流结束
         * @details 对端关闭连接或读到 EOF。
         */
        eof = 3,
        /**
         * @brief 操作会阻塞
         * @details 需要等待更多数据或资源。
         */
        would_block = 4,
        /**
         * @brief 协议错误
         * @details 违反协议约束、非法状态机等。
         */
        protocol_error = 5,
        /**
         * @brief 消息错误
         * @details 长度不足、字段越界、坏消息。
         */
        bad_message = 6,
        /**
         * @brief 参数非法
         * @details 调用方输入不合理。
         */
        invalid_argument = 7,
        /**
         * @brief 不支持的能力/功能
         * @details 版本、命令、特性不支持。
         */
        not_supported = 8,
        /**
         * @brief 消息过大
         * @details 超出限制，防止内存/CPU 被打爆。
         */
        message_too_large = 9,
        /**
         * @brief I/O 错误
         * @details socket 读写失败、系统调用失败等。
         */
        io_error = 10,
        /**
         * @brief 操作超时
         */
        timeout = 11,
        /**
         * @brief 操作被取消
         * @details 取消槽、关闭等触发。
         */
        canceled = 12,
        /**
         * @brief TLS 握手失败
         */
        tls_handshake_failed = 13,
        /**
         * @brief TLS 关闭失败
         * @details shutdown 失败。
         */
        tls_shutdown_failed = 14,
        /**
         * @brief 认证失败
         * @details 密码/凭证校验失败。
         */
        auth_failed = 15,
        /**
         * @brief DNS 解析失败
         */
        dns_failed = 16,
        /**
         * @brief 上游不可达
         * @details 网络不可达或路由失败。
         */
        upstream_unreachable = 17,

        /**
         * @brief 上游拒绝连接
         */
        connection_refused = 18,
        /**
         * @brief 不支持的命令
         * @details 例如 SOCKS5 非 CONNECT 请求。
         */
        unsupported_command = 19,
        /**
         * @brief 不支持的地址类型
         */
        unsupported_address = 20,
        /**
         * @brief 阻塞
         * @details 被黑名单拦截。
         */
        blocked = 21,
        /**
         * @brief 网关错误
         * @details 反向代理路由失败。
         */
        bad_gateway = 22,
        /**
         * @brief 主机不可达
         * @details DNS解析失败或无法路由到主机。
         */
        host_unreachable = 23,

        /**
         * @brief 连接被重置
         * @details TCP连接被对端重置。
         */
        connection_reset = 24,
        /**
         * @brief 网络不可达
         * @details 网络层不可达（如路由失败）。
         */
        network_unreachable = 25,
        /**
         * @brief SSL证书加载失败
         * @details 加载SSL证书文件失败。
         */
        ssl_cert_load_failed = 26,
        /**
         * @brief SSL密钥加载失败
         * @details 加载SSL私钥文件失败。
         */
        ssl_key_load_failed = 27,
        /**
         * @brief SOCKS5认证协商失败
         * @details SOCKS5协议认证方法协商失败。
         */
        socks5_auth_negotiation_failed = 28,
        /**
         * @brief 文件打开失败
         * @details 打开文件失败（权限不足、文件不存在等）。
         */
        file_open_failed = 29,
        /**
         * @brief 配置解析错误
         * @details 配置文件格式错误或内容不合法。
         */
        config_parse_error = 30,
        /**
         * @brief 端口已被占用
         * @details 绑定的端口已被其他进程占用。
         */
        port_already_in_use = 31,
        /**
         * @brief 证书验证失败
         * @details SSL/TLS证书验证失败。
         */
        certificate_verification_failed = 32,
        /**
         * @brief 连接被中止
         * @details 连接在建立过程中被中止。
         */
        connection_aborted = 33,
        /**
         * @brief 资源暂时不可用
         * @details 系统资源暂时不可用（如文件描述符耗尽）。
         */
        resource_unavailable = 34,
        /**
         * @brief TTL过期
         * @details 数据包TTL过期（路由循环检测）。
         */
        ttl_expired = 35,
        /**
         * @brief 内部使用
         * @details 用于表示错误码数量，不用于实际错误处理。
         */
        _count = 36
    };

    /**
     * @brief 获取错误码的零分配描述（用于日志/诊断）
     * @param value 错误码枚举值
     * @return `std::string_view` 错误描述字符串，生命周期与程序相同
     * @note 返回的字符串视图指向静态存储期数据，可安全用于日志和诊断。
     * @warning 不要在错误码描述上执行修改操作，`std::string_view` 为只读视图。
     * @throws 无异常（函数标记为 `noexcept`）
     * @details 将错误码转换为人类可读的字符串描述。该函数设计为零开销。
     *
     * 性能特性：
     * @details - 零分配：返回静态字面量的 `std::string_view`，无动态内存分配；
     * @details - 编译时求值：`constexpr` 函数，大部分调用在编译时完成求值；
     * @details - 无异常：`noexcept` 保证不抛出异常，适合热路径使用。
     *
     * 实现细节：
     * @details - 映射机制：使用 `switch` 语句将每个枚举值映射到对应的字符串字面量；
     * @details - 默认处理：对于未知错误码（理论上不可能出现），返回 "unknown"；
     * @details - 编译优化：编译器可将 `switch` 语句优化为跳转表，提高运行时性能。
     *
     * 使用场景：
     * @details - 日志记录：将错误码转换为可读字符串用于日志输出；
     * @details - 调试信息：生成用户友好的错误信息用于调试和监控；
     * @details - 编译时验证：在静态断言中验证错误码描述的正确性。
     *
     * ```
     * // 使用示例：记录错误日志
     * ngx::gist::code ec = some_operation();
     * if (ngx::gist::failed(ec))
     * {
     *     trace::error("Operation failed: {}", ngx::gist::describe(ec));
     * }
     * // 使用示例：编译时字符串生成
     * constexpr auto error_msg = ngx::gist::describe(ngx::gist::code::io_error);
     * static_assert(error_msg == "io_error");
     * ```
     */
    [[nodiscard]] constexpr std::string_view describe(const code value) noexcept
    {
        switch (value)
        {
        case code::success:
            return "success";
        case code::generic_error:
            return "generic_error";
        case code::parse_error:
            return "parse_error";
        case code::eof:
            return "eof";
        case code::would_block:
            return "would_block";
        case code::protocol_error:
            return "protocol_error";
        case code::bad_message:
            return "bad_message";
        case code::invalid_argument:
            return "invalid_argument";
        case code::not_supported:
            return "not_supported";
        case code::message_too_large:
            return "message_too_large";
        case code::io_error:
            return "io_error";
        case code::timeout:
            return "timeout";
        case code::canceled:
            return "canceled";
        case code::tls_handshake_failed:
            return "tls_handshake_failed";
        case code::tls_shutdown_failed:
            return "tls_shutdown_failed";
        case code::auth_failed:
            return "auth_failed";
        case code::dns_failed:
            return "dns_failed";
        case code::upstream_unreachable:
            return "upstream_unreachable";
        case code::connection_refused:
            return "connection_refused";
        case code::unsupported_command:
            return "unsupported_command";
        case code::unsupported_address:
            return "unsupported_address";
        case code::blocked:
            return "blocked";
        case code::bad_gateway:
            return "bad_gateway";
        case code::host_unreachable:
            return "host_unreachable";
        case code::connection_reset:
            return "connection_reset";
        case code::network_unreachable:
            return "network_unreachable";
        case code::ssl_cert_load_failed:
            return "ssl_cert_load_failed";
        case code::ssl_key_load_failed:
            return "ssl_key_load_failed";
        case code::socks5_auth_negotiation_failed:
            return "socks5_auth_negotiation_failed";
        case code::file_open_failed:
            return "file_open_failed";
        case code::config_parse_error:
            return "config_parse_error";
        case code::port_already_in_use:
            return "port_already_in_use";
        case code::certificate_verification_failed:
            return "certificate_verification_failed";
        case code::connection_aborted:
            return "connection_aborted";
        case code::resource_unavailable:
            return "resource_unavailable";
        case code::ttl_expired:
            return "ttl_expired";
        default:
            return "unknown";
        }
    }

    /**
     * @brief 检查错误码是否表示成功
     * @details 判断给定的错误码是否表示操作成功。该函数是错误处理的基础工具，提供清晰的成功/失败语义。
     *
     * 语义等价：`succeeded(c) == (c == code::success)`
     *
     * 使用场景：
     * @details - 异步操作结果检查：检查 `co_await` 异步操作返回的错误码；
     * @details - 条件判断：替代直接比较 `c == code::success`，提高代码表达力；
     * @details - 编译时验证：在静态断言中验证错误码语义。
     *
     * @param c 错误码枚举值
     * @return 如果错误码为 `code::success` 则返回 `true`，否则返回 `false`
     * @note 对于成功检查，优先使用 `succeeded()` 而非直接比较，提高代码表达力。
     * @warning 不要将此函数用于非错误码类型的值。
     * @throws 无异常（函数标记为 `noexcept`）
     *
     * ```
     * // 使用示例：检查操作成功
     * ngx::gist::code ec = co_await async_operation();
     * if (ngx::gist::succeeded(ec))
     * {
     *     // 处理成功逻辑
     *     trace::info("Operation succeeded");
     * } else
     * {
     *     // 处理失败逻辑
     *     trace::error("Operation failed");
     * }
     * // 编译时检查
     * static_assert(ngx::gist::succeeded(ngx::gist::code::success));
     * static_assert(!ngx::gist::succeeded(ngx::gist::code::io_error));
     * ```
     */
    [[nodiscard]] constexpr bool succeeded(const code c) noexcept
    {
        return c == code::success;
    }

    /**
     * @brief 检查错误码是否表示失败
     * @details 判断给定的错误码是否表示操作失败。该函数是 `succeeded()` 的互补函数，提供清晰的失败检查语义。
     *
     * 语义等价：`failed(c) == (c != code::success)`
     *
     * 使用场景：
     * @details - 错误处理流程：检查异步操作是否失败，触发错误处理逻辑；
     * @details - 条件分支：替代 `!succeeded(c)`，提供更清晰的失败语义；
     * @details - 编译时验证：验证错误码的互补关系，确保逻辑一致性。
     *
     * @param c 错误码枚举值
     * @return 如果错误码不为 `code::success` 则返回 `true`，否则返回 `false`
     * @note 对于失败检查，优先使用 `failed()` 而非 `!succeeded()`，提高代码表达力。
     * @warning 不要将此函数用于非错误码类型的值。
     * @throws 无异常（函数标记为 `noexcept`）
     *
     * ```
     * // 使用示例：检查操作失败
     * ngx::gist::code ec = co_await async_operation();
     * if (ngx::gist::failed(ec))
     * {
     *     // 处理失败逻辑
     *     trace::error("Operation failed: {}", ngx::gist::describe(ec));
     *     co_return;
     * }
     * // 编译时检查
     * static_assert(!ngx::gist::failed(ngx::gist::code::success));
     * static_assert(ngx::gist::failed(ngx::gist::code::connection_refused));
     * // 互补性验证
     * static_assert(ngx::gist::failed(ec) == !ngx::gist::succeeded(ec));
     * ```
     */
    [[nodiscard]] constexpr bool failed(const code c) noexcept
    {
        return !succeeded(c);
    }
}