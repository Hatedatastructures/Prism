/**
 * @file security.hpp
 * @brief 安全异常定义
 * @details 定义 security 异常类，用于处理安全相关的错误，
 * 如认证失败、授权拒绝、证书无效、TLS 协议违规等。
 * 仅用于启动阶段安全配置错误，运行时安全错误应使用
 * 错误码。
 * @note 运行时认证/授权失败应使用错误码而非异常。
 * @warning 不要在热路径中抛出此异常。
 */
#pragma once

#include <prism/exception/deviant.hpp>

namespace psm::exception
{
    /**
     * @class security
     * @brief 安全异常
     * @details 表示安全层相关的异常情况，继承自
     * exception::deviant。用于处理安全配置和初始化
     * 阶段的错误，运行时安全验证失败应使用错误码。
     * @note 类型名称为 SECURITY，在 dump() 输出中
     * 标识异常分类。
     * @warning 异常构造可能分配内存，避免在内存紧张
     * 的安全回调中使用。
     */
    class security : public deviant
    {
    public:
        /**
         * @brief 构造函数（安全错误码）
         * @param err 安全错误码
         * @param loc 源码位置，默认自动获取
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
         * @param loc 源码位置，默认自动获取
         */
        explicit security(psm::fault::code err, std::string_view desc,
                          const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), desc, loc)
        {
        }

        /**
         * @brief 构造函数（向后兼容字符串）
         * @param msg 错误消息
         * @param loc 源码位置，默认自动获取
         * @details 将字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
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
         * @details 将格式化字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
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
         * @details 将格式化字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit security(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @return 异常类型名称，固定为 SECURITY
         * @details 重写基类的虚函数，返回安全异常的
         * 类型标识符，用于异常分类和日志记录。
         */
        [[nodiscard]] std::string_view type_name() const noexcept override { return "SECURITY"; }
    }; // class security
} // namespace psm::exception
