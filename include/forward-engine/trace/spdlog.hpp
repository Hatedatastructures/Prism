#pragma once
#include <boost/asio/awaitable.hpp>
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace ngx::trace
{
    /**
     * @brief 日志追踪系统的配置参数结构体
     *
     * 此结构体用于配置 `spdlog` 日志系统的各项参数，包括文件输出、控制台输出、
     * 日志格式、级别等。所有配置都有合理的默认值。
     *
     * @note 线程安全的配置，可在运行时动态调整部分参数
     * @see 参考 spdlog 文档了解更多细节
     * 
     * @see 文档地址：https://github.com/gabime/spdlog.git
     */
    struct trace_config
    {
        /**
         * @brief 日志文件名（不含路径）
         * @details 例如："app.log"。如果为空，则使用默认名称
         */
        std::string file_name{};

        /**
         * @brief 日志文件存储路径
         * @details 支持相对路径和绝对路径。如果为空，则使用当前目录
         */
        std::filesystem::path path_name{};

        /**
         * @brief 单个日志文件的最大大小（字节）
         * @details 默认 64MB。当文件达到此大小时会自动轮转
         */
        std::size_t max_size = 64U * 1024U * 1024U;

        /**
         * @brief 最大保留的日志文件数量
         * @details 默认 8 个。超过此数量时，最旧的文件将被删除
         */
        std::size_t max_files = 8U;

        /**
         * @brief 异步日志队列大小
         * @details 默认 8192。较大的队列可以处理突发日志，但会增加内存使用
         */
        std::size_t queue_size = 8192U;

        /**
         * @brief 异步日志后台线程数量
         * @details 默认 1 个线程。对于高并发场景可以适当增加
         */
        std::size_t thread_count = 1U;

        /**
         * @brief 是否启用控制台输出
         * @details 默认 true。开发环境建议开启，生产环境可关闭
         */
        bool enable_console = true;

        bool enable_file = true;

        /**
         * @brief 日志级别
         * @details 默认 info 级别。可设置为 trace、debug、info、warn、error、critical
         */
        spdlog::level::level_enum log_level = spdlog::level::info;

        /**
         * @brief 日志格式模式字符串
         * @details 使用 spdlog 格式语法：
         *          %Y-年 %m-月 %d-日 %H-时 %M-分 %S-秒 %e-毫秒
         *          %l-级别 %v-消息内容 %n-日志器名称
         */
        std::string pattern = "[%Y-%m-%d %H:%M:%S.%e][%l] %v";

        /**
         * @brief 日志器名称
         * @details 用于在多个日志器间区分的标识符。默认 "forward_engine"
         */
        std::string trace_name = "forward_engine";
    };  // struct trace_config

    /**
     * @brief 初始化全局日志器
     * @param cfg 配置
     * @note 允许重复调用：后一次会覆盖前一次的 trace_config 配置。
     */
    void init(const trace_config &cfg);

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
        return;
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
        return;
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
        return;
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
        return;
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
        return;
    }
}
