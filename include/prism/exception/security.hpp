/**
 * @file security.hpp
 * @brief 安全异常定义
 * @details 定义了 security 异常类，用于处理安全相关的错误。该异常类
 * 表示安全层错误，如认证失败、授权拒绝、证书无效、TLS 协议违规等。
 * 遵循异常使用原则，仅用于启动阶段安全配置错误，运行时安全错误
 * 应使用错误码。典型应用场景包括 SSL 证书加载失败或格式错误、
 * 配置文件中的认证凭据格式无效、启动时安全策略验证失败、
 * 黑名单/白名单配置解析错误。错误码映射使用 psm::fault::code 中的
 * 安全相关错误码，如 authentication_failed、authorization_denied、
 * certificate_invalid、certificate_expired、certificate_revoked、
 * tls_protocol_violation、tls_handshake_failed、blacklisted、
 * access_denied 等。
 * @note 运行时认证/授权失败（如密码错误）应使用错误码而非异常。
 * @warning 不要在热路径（如每个请求的认证检查）中抛出此异常。
 */
#pragma once

#include <prism/exception/deviant.hpp>

/**
 * @namespace psm::exception
 * @brief 异常处理体系
 * @details 定义了系统中的各类异常基类和具体实现。
 */
namespace psm::exception
{
    /**
     * @class security
     * @brief 安全异常
     * @details 表示安全层相关的异常情况，继承自 exception::deviant。
     * 该异常类用于处理安全配置和初始化阶段的错误，运行时安全验证失败
     * 应使用错误码。错误范围包括认证错误（用户认证失败、令牌无效、
     * 凭据错误）、授权错误（访问权限不足、操作未授权）、证书错误
     * （SSL 证书无效、过期、被吊销）、协议错误（TLS 协议违规、握手失败、
     * 密码套件不匹配）、策略错误（黑名单拦截、访问控制拒绝）。
     * @note 类型名称为 SECURITY，在 dump() 输出中标识异常分类。
     * @warning 异常构造可能分配内存，避免在内存紧张的安全回调中使用。
     * @throws 构造函数可能抛出 std::bad_alloc（如果内存分配失败）。
     */
    class security : public deviant
    {
    public:
        /**
         * @brief 构造函数（安全错误码）
         * @param err 安全错误码
         * @param loc 源码位置（默认自动获取）
         */
        explicit security(::psm::fault::code err,
                          const std::source_location &loc = std::source_location::current())
            : deviant(::psm::fault::make_error_code(err), {}, loc)
        {
        }

        /**
         * @brief 构造函数（安全错误码 + 额外描述）
         * @param err 安全错误码
         * @param desc 额外描述信息
         * @param loc 源码位置（默认自动获取）
         */
        explicit security(psm::fault::code err, std::string_view desc,
                          const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), desc, loc)
        {
        }

        /**
         * @brief 构造函数（向后兼容字符串）
         * @param msg 错误消息
         * @param loc 源码位置（默认自动获取）
         * @details 此构造函数将字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         * @note 建议迁移到错误码构造函数。
         */
        explicit security(const std::string &msg,
                          const std::source_location &loc = std::source_location::current())
            : deviant(msg, loc)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，自动获取位置）
         * @tparam Args 格式化参数类型
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 此构造函数将格式化字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         * @note 建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit security(std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，指定位置）
         * @tparam Args 格式化参数类型
         * @param loc 源码位置
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 此构造函数将格式化字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         * @note 建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit security(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @return 异常类型名称，固定为 SECURITY 字符串视图
         * @details 重写基类 exception::deviant 的虚函数，返回安全异常
         * 的类型标识符。类型名称用于异常分类、日志记录和调试信息显示。
         * 返回值为字符串字面量视图，生命周期与程序相同。
         */
        [[nodiscard]] std::string_view type_name() const noexcept override { return "SECURITY"; }
    };
}
