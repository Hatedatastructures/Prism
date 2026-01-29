/**
 * @file deviant.hpp
 * @brief 异常基类定义
 * @details 定义了所有自定义异常的基类，支持源位置捕获和格式化消息。
 */
#pragma once

#include <stdexcept>
#include <exception>
#include <string>
#include <string_view>
#include <source_location>
#include <format>
#include <filesystem>

/**
 * @namespace ngx::abnormal
 * @brief 异常处理体系
 * @details 定义了系统中的各类异常基类和具体实现。
 * 所有异常均继承自 `abnormal::exception`，支持自动捕获源码位置 (Source Location) 和格式化错误消息。
 */
namespace ngx::abnormal
{
    /**
     * @brief 自定义异常基类
     * @details 继承自 `std::runtime_error`，自动捕获抛出点的位置信息，并支持格式化消息。
     */
    class exception : public std::runtime_error
    {
    public:
        /**
         * @brief 构造函数 (带格式化参数)
         * @tparam Args 参数类型
         * @param loc 源码位置 (默认自动获取)
         * @param fmt 格式化字符串
         * @param args 格式化参数
         */
        template <typename... Args>
        explicit exception(const std::source_location& loc, std::format_string<Args...> fmt, Args&&... args)
            : std::runtime_error(std::format(fmt, std::forward<Args>(args)...))
            , location_(loc)
        {
        }

        /**
         * @brief 构造函数 (普通字符串)
         * @param loc 源码位置
         * @param msg 错误消息
         */
        explicit exception(const std::source_location& loc, const std::string& msg)
            : std::runtime_error(msg)
            , location_(loc)
        {
        }

        /**
         * @brief 获取异常抛出时的位置信息
         * @return const std::source_location& 包含文件名、行号、列号等位置信息
         */
        [[nodiscard]] const std::source_location& location() const noexcept { return location_; }

        /**
         * @brief 获取异常抛出时的文件名
         * @return std::string 文件名（不包含路径）
         */
        [[nodiscard]] std::string filename() const
        {
            return std::filesystem::path(location_.file_name()).filename().string();
        }

        /**
         * @brief 格式化异常信息
         * @details 生成包含文件名、行号、异常类型和错误描述的详细字符串。
         * @return std::string 格式化后的异常信息
         */
        [[nodiscard]] virtual std::string dump() const
        {
            return std::format("[{}:{}] [{}] {}",filename(),location_.line(),
                type_name(),what());
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @details 子类必须实现这个方法，返回自己的类型名称（如 "SECURITY", "NETWORK"）。
         * @return std::string_view 异常类型名称
         */
        [[nodiscard]] virtual std::string_view type_name() const noexcept = 0;

    private:
        std::source_location location_;
    };
}