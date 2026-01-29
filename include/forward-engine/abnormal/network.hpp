/**
 * @file network.hpp
 * @brief 网络异常定义
 * @details 定义了 `network` 异常类，用于处理网络相关的错误。
 */
#pragma once

#include "deviant.hpp"

namespace ngx::abnormal
{
    /**
     * @brief 网络异常
     * @details 网络异常是指在程序运行过程中，由于网络原因（如连接断开、超时、DNS 解析失败等）而导致的异常情况。
     */
    class network : public exception
    {
    public:
        /**
         * @brief 构造函数 (带格式化参数，自动获取位置)
         * @tparam Args 格式化参数类型
         * @param fmt 格式化字符串
         * @param args 格式化参数
         */
        template <typename... Args>
        explicit network(std::format_string<Args...> fmt, Args&&... args)
            : exception(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {}

        /**
         * @brief 构造函数 (带格式化参数，指定位置)
         * @tparam Args 格式化参数类型
         * @param loc 源码位置
         * @param fmt 格式化字符串
         * @param args 格式化参数
         */
        template <typename... Args>
        explicit network(const std::source_location& loc, std::format_string<Args...> fmt, Args&&... args)
            : exception(loc, fmt, std::forward<Args>(args)...)
        {}

        /**
         * @brief 构造函数 (普通字符串)
         * @param msg 错误消息
         * @param loc 源码位置 (默认自动获取)
         */
        explicit network(const std::string& msg,
                               const std::source_location& loc = std::source_location::current())
            : exception(loc, msg)
        {}

    protected:
        [[nodiscard]] std::string_view type_name() const noexcept override { return "NETWORK"; }
    };
}
