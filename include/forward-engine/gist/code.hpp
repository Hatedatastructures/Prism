#pragma once

#include <cstdint>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <boost/system/error_code.hpp>

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
         * @brief 解析失败（格式不合法、字段缺失等）
         */
        parse_error = 2,
        /**
         * @brief 输入流结束（对端关闭连接或读到 EOF）
         */
        eof = 3,
        /**
         * @brief 操作会阻塞（需要等待更多数据/资源）
         */
        would_block = 4,
        /**
         * @brief 协议错误（违反协议约束、非法状态机等）
         */
        protocol_error = 5,
        /**
         * @brief 消息错误（长度不足、字段越界、坏消息）
         */
        bad_message = 6,
        /**
         * @brief 参数非法（调用方输入不合理）
         */
        invalid_argument = 7,
        /**
         * @brief 不支持的能力/功能（版本、命令、特性不支持）
         */
        not_supported = 8,
        /**
         * @brief 消息过大（超出限制，防止内存/CPU 被打爆）
         */
        message_too_large = 9,
        /**
         * @brief I/O 错误（socket 读写失败、系统调用失败等）
         */
        io_error = 10,
        /**
         * @brief 操作超时
         */
        timeout = 11,
        /**
         * @brief 操作被取消（取消槽、关闭等触发）
         */
        canceled = 12,
        /**
         * @brief TLS 握手失败
         */
        tls_handshake_failed = 13,
        /**
         * @brief TLS 关闭失败（shutdown 失败）
         */
        tls_shutdown_failed = 14,
        /**
         * @brief 认证失败（密码/凭证校验失败）
         */
        auth_failed = 15,
        /**
         * @brief DNS 解析失败
         */
        dns_failed = 16,
        /**
         * @brief 上游不可达（网络不可达/路由失败）
         */
        upstream_unreachable = 17,
        /**
         * @brief 上游拒绝连接
         */
        connection_refused = 18,
        /**
         * @brief 不支持的命令（例如 SOCKS5 非 CONNECT）
         */
        unsupported_command = 19,
        /**
         * @brief 不支持的地址类型
         */
        unsupported_address = 20,
        /**
         * @brief 阻塞（被黑名单拦截）
         */
        blocked = 21,
        /**
         * @brief 网关错误（反向代理路由失败）
         */
        bad_gateway = 22,
        /**
         * @brief 主机不可达（DNS解析失败）
         */
        host_unreachable = 23
    };

    /**
     * @brief 获取错误码的零分配描述（用于日志/诊断）
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
        default:
            return "unknown";
        }
    }

    /**
     * @brief `std::error_code` 分类（用于与 `std::error_code` 体系对接）
     */
    class status_category : public std::error_category
    {
    public:
        [[nodiscard]] const char* name() const noexcept override
        {
            return "ngx::gist";
        }

        [[nodiscard]] std::string message(int c) const override
        {
            return std::string(describe(static_cast<code>(c)));
        }
    };

    /**
     * @brief 获取状态分类单例
     */
    inline const std::error_category& category() noexcept
    {
        static status_category instance;
        return instance;
    }

    /**
     * @brief 创建错误码
     */
    inline std::error_code make_error_code(code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
}

namespace std
{
    template <>
    struct is_error_code_enum<ngx::gist::code> : true_type {};
}

namespace boost::system
{
    template <>
    struct is_error_code_enum<ngx::gist::code> : std::true_type {};

    class gist_category final : public boost::system::error_category
    {
    public:
        [[nodiscard]] const char* name() const noexcept override
        {
            return "ngx::gist";
        }

        [[nodiscard]] std::string message(int c) const override
        {
            return std::string(ngx::gist::describe(static_cast<ngx::gist::code>(c)));
        }
    };

    inline const boost::system::error_category& category() noexcept
    {
        static gist_category instance;
        return instance;
    }

    inline boost::system::error_code make_error_code(const ngx::gist::code c) noexcept
    {
        return {static_cast<int>(c), category()};
    }
}
