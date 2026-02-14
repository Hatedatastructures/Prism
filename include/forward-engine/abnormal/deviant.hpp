/**
 * @file deviant.hpp
 * @brief 异常基类定义
 * @details 定义了所有自定义异常的基类，支持源位置捕获和格式化消息。
 * 该模块是项目异常处理系统的核心，基于 `std::error_code` 架构，提供结构化异常信息，
 * 遵循"热路径无异常"原则：仅用于启动阶段配置错误或致命错误，热路径使用错误码。
 *
 * 设计特性：
 * - 错误码存储：核心存储 `std::error_code`，支持标准库和项目错误码；
 * - 源位置捕获：自动捕获异常抛出点的文件名、行号、函数名；
 * - 格式化输出：提供 `dump()` 方法生成结构化异常报告；
 * - 类型安全：抽象基类要求子类实现类型名称。
 *
 * 异常使用原则：
 * 1. 热路径禁用：网络 `I/O`、协议解析、数据转发等热路径严禁抛异常；
 * 2. 冷路径适用：启动阶段配置加载失败、资源初始化失败等；
 * 3. 错误码优先：尽可能使用 `ngx::gist::code` 错误码返回值。
 *
 * @note 所有自定义异常应继承自 `abnormal::exception` 并实现 `type_name()`。
 * @warning 异常构造和复制可能分配内存，避免在内存紧张时使用。
 */
#pragma once

#include <stdexcept>
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
 * @warning - 该命名空间的内容主要用于冷路径错误处理，热路径应使用错误码。
 * @warning - 异常不应作为正常的控制流机制，仅用于错误恢复。
 * @throws 异常类本身的构造函数可能抛出 `std::bad_alloc`（内存不足）
 * @details 定义了系统中的各类异常基类和具体实现。
 * 该命名空间实现了基于 `std::error_code` 的现代异常架构，包含：
 * @details - 异常基类 (`exception`)：所有自定义异常的公共基类；
 * @details - 分类异常：`network`、`security`、`protocol` 等分类异常；
 * @details - 工具函数：异常处理辅助函数。
 *
 *
 * 异常层次：
 *
 * ```
 * std::runtime_error
 * └── ngx::abnormal::exception (抽象基类)
 *     ├── ngx::abnormal::network (网络错误)
 *     ├── ngx::abnormal::security (安全错误)
 *     └── ngx::abnormal::protocol (协议错误)
 * ```
 */
namespace ngx::abnormal
{
    /**
     * @class exception
     * @brief 项目异常基类
     * @note 该类是抽象基类，不能直接实例化，必须通过子类使用。
     * @warning 异常对象可能较大（包含字符串和位置信息），避免在内存紧张时使用。
     * @throws 构造函数可能抛出 `std::bad_alloc`（如果内存分配失败）
     * @details 继承自 `std::runtime_error`，核心存储 `std::error_code`，自动捕获抛出点的位置信息，并支持格式化消息。
     * 该类是所有项目自定义异常的抽象基类，强制子类提供类型分类。
     *
     * 核心特性：
     * @details - 错误码存储：存储 `std::error_code`，支持标准库和项目错误码；
     * @details - 源位置捕获：自动记录异常抛出点的文件名、行号、函数名（`std::source_location`）；
     * @details - 格式化输出：`dump()` 方法生成结构化异常报告；
     * @details - 抽象接口：纯虚函数 `type_name()` 强制子类提供类型名称。
     *
     *
     * ```
     * // 使用示例：定义子类
     * class custom_exception : public ngx::abnormal::exception
     * {
     * public:
     *     using exception::exception;  // 继承构造函数
     *
     * protected:
     *     std::string_view type_name() const noexcept override
     *     {
     *         return "CUSTOM_ERROR";
     *     }
     * };
     *
     * // 使用示例：抛出异常
     * try
     * {
     *     connect_to_server();
     * } catch (const custom_exception& e)
     * {
     *     // 处理自定义异常
     *     trace::error("Custom error: {}", e.dump());
     * } catch (const exception& e)
     * {
     *     // 处理其他异常
     *     trace::error("General error: {}", e.dump());
     * }
     * ```
     *
     */
    class exception : public std::runtime_error
    {
    public:
        /**
         * @brief 主构造函数（错误码 + 可选描述）
         * @details 使用错误码和可选描述构造异常，自动捕获抛出点的源码位置。
         * 这是异常构造的首选方式，提供结构化的错误信息。
         *
         * 构造流程：
         * @details - 1. 调用 `create_what()` 组合错误消息（错误码描述 + 额外描述）；
         * @details - 2. 初始化基类 `std::runtime_error` 包含组合消息；
         * @details - 3. 存储错误码和源码位置。
         *
         * @param ec 错误码（`std::error_code`），包含错误值和分类
         * @param desc 额外描述信息（可选），提供上下文或具体原因
         * @param loc 源码位置（默认自动获取），使用 `std::source_location::current()`
         * @note 使用默认 `loc` 参数自动捕获调用位置，无需手动传递。
         * @warning 额外描述不应过长，避免内存浪费。
         * @throws `std::bad_alloc` 如果 `create_what()` 字符串分配失败

         * ```
         * // 使用示例：标准错误码
         * throw abnormal::exception(std::make_error_code(std::errc::connection_refused),"Target server is not accepting connections");
         * // 使用示例：项目错误码
         * throw abnormal::exception(gist::code::timeout,"Operation timed out after 30 seconds");
         * // 使用示例：手动指定位置（不推荐）
         * throw abnormal::exception(ec, desc, std::source_location::current());
         * ```
         *
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
        explicit exception(const std::string &msg, const std::source_location &loc = std::source_location::current())
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
         * @note 输出格式：`[filename:line] [TYPE:value] description`
         */
        [[nodiscard]] virtual std::string dump() const
        {
            return std::format("[{}:{}] [{}:{}] {}", filename(), location_.line(),
                               type_name(), ec_.value(), std::runtime_error::what());
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @details 子类必须实现这个方法，返回自己的类型名称（如 `"SECURITY"`, `"NETWORK"`）。
         * @return `std::string_view` 异常类型名称
         */
        [[nodiscard]] virtual std::string_view type_name() const noexcept = 0;

    private:
        /**
         * @brief 构建 `what()` 字符串
         * @param ec 错误码
         * @param desc 额外描述
         * @return `std::string` 组合后的错误消息
         */
        static std::string create_what(const std::error_code &ec, std::string_view desc)
        {
            if (desc.empty())
            {
                return ec.message();
            }
            return std::format("{}: {}", ec.message(), desc);
        }

        std::error_code ec_;            // 错误码
        std::source_location location_; // 异常发生的位置
    };
}