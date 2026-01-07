#pragma once
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>
#include <filesystem>
#include <memory>
#include <string_view>
#include <utility>
#include "config.hpp"

namespace ngx::trace
{

    /**
     * @brief 初始化全局日志器
     * @param cfg 配置
     * @note 允许重复调用：后一次会覆盖前一次的 config 配置。
     */
    void init(const config &cfg);

    /**
     * @brief 关闭日志器并释放线程池资源
     * @note 该函数会尝试刷盘后释放资源。
     */
    void shutdown();

    /**
     * @brief 获取当前日志器（可能为空）
     */
    [[nodiscard]] std::shared_ptr<spdlog::logger> recorder() noexcept;

    /**
     * @brief 记录调试日志
     * @details 日志级别为 debug。
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
     * @details 日志级别为 info。
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
     * @details 日志级别为 warn。
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
     * @details 日志级别为 error。
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
     * @details 日志级别为 critical，会立即触发程序终止。
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
