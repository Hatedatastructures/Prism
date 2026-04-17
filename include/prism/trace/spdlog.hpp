/**
 * @file spdlog.hpp
 * @brief 日志接口封装
 * @details 封装 spdlog 库，提供统一的日志记录接口，
 * 支持多级别日志输出。所有接口内部捕获异常，确保
 * 日志失败不影响业务逻辑。
 * @note 允许重复调用 init，后一次覆盖前一次。
 * @warning 必须在程序退出前调用 shutdown 释放
 * 线程池资源。
 */
#pragma once

#include <memory>
#include <string_view>
#include <utility>

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

#include <prism/trace/config.hpp>

namespace psm::trace
{
    /**
     * @brief 初始化全局日志器
     * @param cfg 日志配置对象
     * @details 根据配置创建异步日志器，支持文件和控制台
     * 双输出。如果已存在日志器，会先销毁旧的再创建新的。
     */
    void init(const config &cfg);

    /**
     * @brief 关闭日志器并释放线程池资源
     * @details 将缓冲区日志刷盘后释放资源，调用后所有
     * 日志接口不再产生输出，直到再次调用 init。
     */
    void shutdown();

    /**
     * @brief 获取当前日志器
     * @return 全局日志器的 shared_ptr，未初始化则为空
     * @details 提供对底层 spdlog 日志器的直接访问，
     * 用于高级场景如自定义 sink、手动刷盘等。
     */
    [[nodiscard]] std::shared_ptr<spdlog::logger> recorder() noexcept;

    /**
     * @brief 记录调试日志
     * @tparam Args 格式化参数类型
     * @param fmt 格式化字符串，支持 fmt 库语法
     * @param args 格式化参数
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
     * @param fmt 格式化字符串，支持 fmt 库语法
     * @param args 格式化参数
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
     * @param fmt 格式化字符串，支持 fmt 库语法
     * @param args 格式化参数
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
     * @param fmt 格式化字符串，支持 fmt 库语法
     * @param args 格式化参数
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
     * @param fmt 格式化字符串，支持 fmt 库语法
     * @param args 格式化参数
     * @warning 致命错误通常意味着程序即将终止，
     * 但此函数不会自动终止程序。
     */
    template <typename... Args>
    void fatal(const std::string_view fmt, Args &&...args)
    {
        if (const auto rec = recorder())
        {
            rec->critical(spdlog::fmt_lib::runtime(fmt), std::forward<Args>(args)...);
        }
    }
} // namespace psm::trace
