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
#include <system_error>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/gist/compatible.hpp>

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
     * @details 继承自 `std::runtime_error`，核心存储 `std::error_code`，自动捕获抛出点的位置信息，并支持格式化消息。
     */
    class exception : public std::runtime_error
    {
    public:
        /**
         * @brief 主构造函数（错误码 + 可选描述）
         * @param ec 错误码
         * @param desc 额外描述信息（可选）
         * @param loc 源码位置（默认自动获取）
         */
        explicit exception(std::error_code ec, std::string_view desc = {},
                           const std::source_location &loc = std::source_location::current())
            : std::runtime_error(create_what(ec, desc)), ec_(ec), location_(loc)
        {
        }

        /**
         * @brief 构造函数（向后兼容字符串）
         * @param msg 错误消息
         * @param loc 源码位置（默认自动获取）
         * @note 此构造函数将字符串转换为 `generic_error` 错误码，建议迁移到错误码构造函数。
         */
        explicit exception(const std::string &msg,
                           const std::source_location &loc = std::source_location::current())
            : exception(std::error_code(static_cast<int>(gist::code::generic_error), gist::category()), msg, loc)
        {
        }

        /**
         * @brief 构造函数（带格式化参数）
         * @tparam Args 参数类型
         * @param loc 源码位置（默认自动获取）
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @note 此构造函数将格式化字符串转换为 `generic_error` 错误码，建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit exception(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : exception(std::format(fmt, std::forward<Args>(args)...), loc)
        {
        }

        /**
         * @brief 获取异常的错误码
         * @return const std::error_code& 错误码引用
         */
        [[nodiscard]] const std::error_code &error_code() const noexcept { return ec_; }

        /**
         * @brief 获取异常抛出时的位置信息
         * @return const std::source_location& 包含文件名、行号、列号等位置信息
         */
        [[nodiscard]] const std::source_location &location() const noexcept { return location_; }

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
         * @details 生成包含文件名、行号、异常类型、错误码和错误描述的详细字符串。
         * @return std::string 格式化后的异常信息
         * @note 输出格式：[filename:line] [TYPE:value] description
         */
        [[nodiscard]] virtual std::string dump() const
        {
            return std::format("[{}:{}] [{}:{}] {}",
                               filename(), location_.line(),
                               type_name(), ec_.value(),
                               std::runtime_error::what());
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @details 子类必须实现这个方法，返回自己的类型名称（如 "SECURITY", "NETWORK"）。
         * @return std::string_view 异常类型名称
         */
        [[nodiscard]] virtual std::string_view type_name() const noexcept = 0;

    private:
        /**
         * @brief 构建 what() 字符串
         * @param ec 错误码
         * @param desc 额外描述
         * @return 组合后的错误消息
         */
        static std::string create_what(const std::error_code &ec, std::string_view desc)
        {
            if (desc.empty())
            {
                return ec.message();
            }
            return std::format("{}: {}", ec.message(), desc);
        }

        std::error_code ec_;
        std::source_location location_;
    };
}