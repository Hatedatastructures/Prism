/**
 * @file code.hpp
 * @brief 全局错误码枚举定义
 * @details 定义了 ForwardEngine 系统通用的错误码枚举及相关基础辅助函数。
 * 标准库兼容性支持（std::error_code 和 boost::system::error_code）请参见 compatible.hpp 文件。
 */
#pragma once

#include <string_view>

/**
 * @namespace ngx::gist
 * @brief 基础设置与标准类型
 * @details 定义了项目通用的基础类型、错误码枚举 (Error Code) 以及跨平台兼容性宏。
 * 它是整个项目的"基石"，不依赖其他高级模块。
 */
namespace ngx::gist
{
    /**
     * @brief ForwardEngine 全局错误码
     * @details
     * - 热路径（网络 I/O、协议解析、数据转发）严禁抛异常，必须使用该错误码返回值进行流控。
     * - 异常仅允许用于启动阶段（例如配置加载失败）或致命错误（例如内存耗尽）。
     * - 该枚举是轻量 Value Object（4 bytes），不包含任何动态分配。
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
     * @param value 错误码
     * @return 错误描述字符串
     * @note 返回静态字面量，不进行堆分配。
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
     * @param c 错误码
     * @return 如果错误码为 `success` 则返回 `true`，否则返回 `false`
     */
    [[nodiscard]] constexpr bool succeeded(const code c) noexcept
    {
        return c == code::success;
    }

    /**
     * @brief 检查错误码是否表示失败
     * @param c 错误码
     * @return 如果错误码不为 `success` 则返回 `true`，否则返回 `false`
     */
    [[nodiscard]] constexpr bool failed(const code c) noexcept
    {
        return !succeeded(c);
    }
}