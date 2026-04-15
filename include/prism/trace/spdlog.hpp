/**
 * @file spdlog.hpp
 * @brief 日志接口封装
 * @details 封装 spdlog 库，提供统一的日志记录接口，支持多级别日志输出。
 * 所有日志接口内部捕获异常，确保日志失败不影响业务逻辑。
 * @note 允许重复调用 init，后一次会覆盖前一次的配置。
 * @warning 必须在程序退出前调用 shutdown 释放线程池资源。
 */
#pragma once

#include <memory>
#include <string_view>
#include <utility>

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

#include <prism/trace/config.hpp>

/**
 * @namespace psm::trace
 * @brief 日志与可观测性系统
 * @details 基于 spdlog 实现高性能异步日志记录，支持多级别、
 * 多目标的日志输出，是可观测性基础设施的核心组件。
 */
namespace psm::trace
{
    /**
     * @brief 初始化全局日志器
     * @param cfg 日志配置对象
     * @details 根据配置创建异步日志器，支持文件和控制台双输出。
     * 如果已存在日志器，会先销毁旧的再创建新的。
     * @note 允许重复调用，后一次会覆盖前一次的配置。
     */
    void init(const config &cfg);

    /**
     * @brief 关闭日志器并释放线程池资源
     * @details 该函数会尝试将缓冲区日志刷盘后释放资源。
     * 调用后所有日志接口将不再产生输出，直到再次调用 init 重新初始化。
     * @note 建议在程序退出前调用，确保所有日志都已刷盘。
     */
    void shutdown();

    /**
     * @brief 获取当前日志器
     * @return 返回当前全局日志器的 shared_ptr，如果未初始化则为空
     * @details 提供对底层 spdlog 日志器的直接访问，
     * 用于高级场景如自定义 sink、手动刷盘等。
     * @note 返回的指针可能为空，调用方需检查有效性。
     */
    [[nodiscard]] std::shared_ptr<spdlog::logger> recorder() noexcept;

    /**
     * @brief 记录调试日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串，支持 fmt 库格式化语法
     * @param args 格式化参数
     * @details 日志级别为 debug，用于开发调试。
     * 仅在日志级别设置为 debug 或更低时输出。
     * @note 调用前需确保已调用 init 初始化日志系统。
     */
    template <typename... Args>
    void debug(const std::string_view fmt, Args &&...args)
    {
        if (const auto rec = recorder())
        {
            rec->debug(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
        }
    }

    /**
     * @brief 记录信息日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串，支持 fmt 库格式化语法
     * @param args 格式化参数
     * @details 日志级别为 info，用于记录一般性运行信息。
     * 仅在日志级别设置为 info 或更低时输出。
     * @note 调用前需确保已调用 init 初始化日志系统。
     */
    template <typename... Args>
    void info(const std::string_view fmt, Args &&...args)
    {
        if (const auto rec = recorder())
        {
            rec->info(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
        }
    }

    /**
     * @brief 记录警告日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串，支持 fmt 库格式化语法
     * @param args 格式化参数
     * @details 日志级别为 warn，用于记录潜在问题或非预期情况。
     * 仅在日志级别设置为 warn 或更低时输出。
     * @note 调用前需确保已调用 init 初始化日志系统。
     */
    template <typename... Args>
    void warn(const std::string_view fmt, Args &&...args)
    {
        if (const auto rec = recorder())
        {
            rec->warn(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
        }
    }

    /**
     * @brief 记录错误日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串，支持 fmt 库格式化语法
     * @param args 格式化参数
     * @details 日志级别为 error，用于记录运行错误，但不影响程序继续运行。
     * 仅在日志级别设置为 error 或更低时输出。
     * @note 调用前需确保已调用 init 初始化日志系统。
     */
    template <typename... Args>
    void error(const std::string_view fmt, Args &&...args)
    {
        if (const auto rec = recorder())
        {
            rec->error(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
        }
    }

    /**
     * @brief 记录致命错误日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串，支持 fmt 库格式化语法
     * @param args 格式化参数
     * @details 日志级别为 critical，通常用于不可恢复的错误。
     * 始终输出，不受日志级别过滤影响。
     * @note 调用前需确保已调用 init 初始化日志系统。
     * @warning 致命错误通常意味着程序即将终止，但此函数不会自动终止程序。
     */
    template <typename... Args>
    void fatal(const std::string_view fmt, Args &&...args)
    {
        if (const auto rec = recorder())
        {
            rec->critical(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
        }
    }
}
