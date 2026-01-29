/**
 * @file spdlog.hpp
 * @brief 日志接口封装
 * @details 封装 spdlog 库，提供统一的日志记录接口，支持多级别日志输出。
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
