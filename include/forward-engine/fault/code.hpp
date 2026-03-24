/**
 * @file code.hpp
 * @brief 全局错误码枚举定义
 * @details 定义 ForwardEngine 系统通用的错误码枚举及相关基础辅助函数。
 * 该错误码系统是项目异常处理的基石，遵循"热路径无异常"原则：网络
 * I/O、协议解析、数据转发等热路径严禁抛异常，必须使用错误码返回值
 * 进行流控。典型应用场景包括网络 I/O 操作的异步返回、协议解析失败
 * 的具体错误、路由转发的网络层错误以及运行时配置验证等。
 * 错误码映射机制支持 std::error_code 兼容，通过 compatible.hpp 实现
 * std::is_error_code_enum 特化和 make_error_code() 转换；同时支持与
 * Boost.System 无缝互操作。分类映射通过 exception 模块异常类映射到
 * network/security/protocol 分类，输出格式为 [Category:Value] Description。
 * @note 异常仅允许用于启动阶段或致命错误，例如配置加载失败或内存耗尽。
 * @warning 错误码描述函数 describe() 返回静态字面量，保证零分配，可用于
 * 热路径日志。
 */
#pragma once

#include <string_view>

/**
 * @namespace ngx::fault
 * @brief 基础设置与标准类型
 * @details 定义项目通用的基础类型、错误码枚举以及跨平台兼容性宏。
 * 该命名空间是整个项目的基石模块，不依赖其他高级模块，为上层组件
 * 提供稳定的基础设施支持。内容包括错误码枚举定义、错误码转换函数、
 * 标准库兼容性特化等核心功能。
 * @note 该命名空间的内容应保持最小化，避免功能膨胀。
 * @warning 修改基础类型可能破坏整个项目的 ABI 兼容性，需进行充分测试。
 */
namespace ngx::fault
{
    /**
     * @enum code
     * @brief ForwardEngine 全局错误码
     * @details 表示系统运行时可能出现的所有错误情况。该枚举是错误处理
     * 系统的核心，遵循"热路径无异常"原则。所有错误码值均为非负整数，
     * 零值表示成功，非零值表示各类错误。错误码按功能分组：通用错误
     * (1-10)、网络错误 (11-18)、协议错误 (19-25)、安全错误 (26-32)、
     * 系统错误 (33-36)。
     * @note 枚举值 _count 仅用于内部统计，不应用于实际错误处理。
     * @warning 错误码比较应使用 == 运算符，不要依赖具体的整数值。
     * @throws 无异常（枚举类型本身不抛出异常）
     */
    enum class code : int
    {
        success = 0,                                  // 操作成功
        generic_error = 1,                            // 通用错误
        parse_error = 2,                              // 解析错误
        eof = 3,                                      // 到达文件末尾
        would_block = 4,                              // 操作将阻塞
        protocol_error = 5,                           // 协议错误
        bad_message = 6,                              // 消息格式错误
        invalid_argument = 7,                         // 无效参数
        not_supported = 8,                            // 不支持的操作
        message_too_large = 9,                        // 消息过大
        io_error = 10,                                // I/O 错误
        timeout = 11,                                 // 操作超时
        canceled = 12,                                // 操作被取消
        tls_handshake_failed = 13,                    // TLS 握手失败
        tls_shutdown_failed = 14,                     // TLS 关闭失败
        auth_failed = 15,                             // 认证失败
        dns_failed = 16,                              // DNS 解析失败
        upstream_unreachable = 17,                    // 上游服务器不可达
        connection_refused = 18,                      // 连接被拒绝
        unsupported_command = 19,                     // 不支持的命令
        unsupported_address = 20,                     // 不支持的地址类型
        blocked = 21,                                 // 请求被阻止
        bad_gateway = 22,                             // 网关错误
        host_unreachable = 23,                        // 主机不可达
        connection_reset = 24,                        // 连接被重置
        network_unreachable = 25,                     // 网络不可达
        ssl_cert_load_failed = 26,                    // SSL 证书加载失败
        ssl_key_load_failed = 27,                     // SSL 密钥加载失败
        socks5_auth_negotiation_failed = 28,           // SOCKS5 认证协商失败
        file_open_failed = 29,                        // 文件打开失败
        config_parse_error = 30,                      // 配置解析错误
        port_already_in_use = 31,                     // 端口已被占用
        certificate_verification_failed = 32,         // 证书验证失败
        connection_aborted = 33,                      // 连接被中止
        resource_unavailable = 34,                    // 资源不可用
        ttl_expired = 35,                             // TTL 已过期
        forbidden = 36,                               // 禁止访问
        ipv6_disabled = 37,                           // IPv6 被禁用
        _count = 38                                   // 错误码总数（内部使用）
    };

    /**
     * @brief 获取错误码的零分配描述
     * @param value 错误码枚举值
     * @return 错误描述字符串视图，生命周期与程序相同
     * @details 将错误码转换为人类可读的字符串描述。该函数设计为零
     * 开销，返回的字符串视图指向静态存储期数据，可安全用于日志和
     * 诊断。对于未知错误码返回 "unknown"。该函数可在编译时求值，
     * 适用于静态断言等场景。
     * @note 返回的字符串视图指向静态存储期数据，可安全用于日志和诊断。
     * @warning 不要在错误码描述上执行修改操作，std::string_view 为只读。
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
        case code::forbidden:
            return "forbidden";
        case code::ipv6_disabled:
            return "ipv6_disabled";
        default:
            return "unknown";
        }
    }

    /**
     * @brief 检查错误码是否表示成功
     * @param c 错误码枚举值
     * @return 如果错误码为 code::success 则返回 true，否则返回 false
     * @details 判断给定的错误码是否表示操作成功。该函数是错误处理的
     * 基础工具，提供清晰的成功/失败语义。语义等价于 c == code::success。
     * 使用场景包括异步操作结果检查、条件判断替代直接比较、编译时验证
     * 错误码语义等。该函数标记为 constexpr 和 noexcept，可在编译时求值。
     * @note 对于成功检查，优先使用 succeeded() 而非直接比较，提高代码表达力。
     * @warning 不要将此函数用于非错误码类型的值。
     */
    [[nodiscard]] constexpr bool succeeded(const code c) noexcept
    {
        return c == code::success;
    }

    /**
     * @brief 检查错误码是否表示失败
     * @param c 错误码枚举值
     * @return 如果错误码不为 code::success 则返回 true，否则返回 false
     * @details 判断给定的错误码是否表示操作失败。该函数是 succeeded()
     * 的互补函数，通过简单取反实现，提供清晰的失败语义。语义等价于
     * c != code::success。使用场景包括错误处理流程检查异步操作是否失败、
     * 条件分支替代 !succeeded(c)、编译时验证错误码互补关系等。
     * @note 对于失败检查，优先使用 failed() 而非 !succeeded()，提高代码表达力。
     * @warning 不要将此函数用于非错误码类型的值。
     */
    [[nodiscard]] constexpr bool failed(const code c) noexcept
    {
        return !succeeded(c);
    }
}
