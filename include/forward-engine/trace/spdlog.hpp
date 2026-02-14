/**
 * @file spdlog.hpp
 * @brief 日志接口封装
 * @details 封装 spdlog 库，提供统一的日志记录接口，支持多级别日志输出。该模块是 ForwardEngine 可观测性系统的核心日志接口，提供高性能的异步日志记录能力。
 *
 * 设计原理：
 * @details - 异步日志：使用 spdlog 异步日志器，后台线程刷盘避免阻塞业务线程；
 * @details - 异常安全：所有日志接口捕获异常，确保日志失败不影响业务逻辑；
 * @details - 格式化支持：使用 fmt 库提供高性能的格式化能力；
 * @details - 全局访问：提供全局日志器，无需手动传递日志器实例。
 *
 * 日志级别：
 * @details - debug：调试信息，用于开发调试；
 * @details - info：一般信息，记录正常运行状态；
 * @details - warn：警告信息，记录潜在问题；
 * @details - error：错误信息，记录运行错误但不影响程序继续运行；
 * @details - fatal：致命错误，通常用于不可恢复的错误。
 *
 * 使用流程：
 * @details 1. 调用 init() 初始化日志系统；
 * @details 2. 使用 debug/info/warn/error/fatal 记录日志；
 * @details 3. 程序退出时调用 shutdown() 关闭日志系统。
 *
 * @note 允许重复调用 init()，后一次会覆盖前一次的配置。
 * @warning 必须在程序退出前调用 shutdown() 释放线程池资源。
 */
#pragma once

#include <memory>
#include <string_view>
#include <utility>

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

#include <forward-engine/trace/config.hpp>

/**
 * @namespace ngx::trace
 * @brief 日志与可观测性系统
 * @details 负责系统的日志记录、性能监控和链路追踪。
 */
namespace ngx::trace
{

    /**
     * @brief 初始化全局日志器
     * @param cfg 日志配置对象
     * @note 允许重复调用：后一次会覆盖前一次的 config 配置。
     */
    void init(const config &cfg);

    /**
     * @brief 关闭日志器并释放线程池资源
     * @note 该函数会尝试将缓冲区日志刷盘后释放资源。
     */
    void shutdown();

    /**
     * @brief 获取当前日志器
     * @return 返回当前全局日志器的 shared_ptr，如果未初始化可能为空。
     */
    [[nodiscard]] std::shared_ptr<spdlog::logger> recorder() noexcept;

    /**
     * @brief 记录调试日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串
     * @param args 格式化参数
     * @details 日志级别为 debug，用于开发调试。
     */
    template <typename... Args>
    void debug(const std::string_view fmt, Args &&...args)
    {
        try
        {
            if (const auto rec = recorder())
            {
                rec->debug(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
            }
        }
        catch (...)
        {
        }
    }

    /**
     * @brief 记录信息日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串
     * @param args 格式化参数
     * @details 日志级别为 info，用于记录一般性运行信息。
     */
    template <typename... Args>
    void info(const std::string_view fmt, Args &&...args)
    {
        try
        {
            if (const auto rec = recorder())
            {
                rec->info(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
            }
        }
        catch (...)
        {
        }
    }

    /**
     * @brief 记录警告日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串
     * @param args 格式化参数
     * @details 日志级别为 warn，用于记录潜在问题或非预期情况。
     */
    template <typename... Args>
    void warn(const std::string_view fmt, Args &&...args)
    {
        try
        {
            if (const auto rec = recorder())
            {
                rec->warn(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
            }
        }
        catch (...)
        {
        }
    }

    /**
     * @brief 记录错误日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串
     * @param args 格式化参数
     * @details 日志级别为 error，用于记录运行错误，但不影响程序继续运行。
     */
    template <typename... Args>
    void error(const std::string_view fmt, Args &&...args)
    {
        try
        {
            if (const auto rec = recorder())
            {
                rec->error(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
            }
        }
        catch (...)
        {
        }
    }

    /**
     * @brief 记录致命错误日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串
     * @param args 格式化参数
     * @details 日志级别为 critical，通常用于不可恢复的错误，会立即触发程序终止。
     */
    template <typename... Args>
    void fatal(const std::string_view fmt, Args &&...args)
    {
        try
        {
            if (const auto rec = recorder())
            {
                rec->critical(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
            }
        }
        catch (...)
        {
        }
    }
}
