/**
 * @file network.hpp
 * @brief 网络异常定义
 * @details 定义 network 异常类，用于处理网络配置和
 * 初始化阶段的错误。运行时网络 I/O 错误应使用错误码
 * 而非异常。错误范围包括连接错误、超时错误、可达性
 * 错误和协议错误。
 * @note 运行时网络 I/O 错误应使用错误码而非异常。
 * @warning 不要在热路径中抛出此异常。
 */
#pragma once

#include <prism/exception/deviant.hpp>

namespace psm::exception
{
    /**
     * @class network
     * @brief 网络异常
     * @details 表示网络层相关的异常情况，继承自
     * exception::deviant。用于处理网络配置和初始化
     * 阶段的错误，运行时网络错误应使用错误码。
     * @note 类型名称为 NETWORK，在 dump() 输出中
     * 标识异常分类。
     * @warning 异常构造可能分配内存，避免在内存紧张
     * 的网络回调中使用。
     */
    class network : public deviant
    {
    public:
        /**
         * @brief 构造函数（网络错误码）
         * @param err 网络错误码
         * @param loc 源码位置，默认自动获取
         */
        explicit network(const fault::code err,
                         const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), {}, loc)
        {
        }

        /**
         * @brief 构造函数（网络错误码 + 额外描述）
         * @param err 网络错误码
         * @param desc 额外描述信息
         * @param loc 源码位置，默认自动获取
         */
        explicit network(const fault::code err, std::string_view desc,
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
        explicit network(const std::string &msg,
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
        explicit network(std::format_string<Args...> fmt, Args &&...args)
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
        explicit network(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @return 异常类型名称，固定为 NETWORK
         * @details 重写基类的虚函数，返回网络异常的
         * 类型标识符，用于异常分类和日志记录。
         */
        [[nodiscard]] std::string_view type_name() const noexcept override { return "NETWORK"; }
    }; // class network
} // namespace psm::exception
