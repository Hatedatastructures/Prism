/**
 * @file config.hpp
 * @brief 日志系统配置
 * @details 定义 spdlog 日志系统的配置参数，支持异步日志记录、
 * 日志轮转和多目标输出。所有字符串字段使用 memory::string 类型，
 * 配合 PMR 分配器减少堆碎片。
 * @note 配置字段使用 memory::string 而非 std::string，减少堆分配。
 * @warning 异步日志队列满时可能阻塞或丢弃日志，需合理设置 queue_size。
 */
#pragma once

#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::trace
 * @brief 日志与可观测性系统
 * @details 基于 spdlog 实现高性能异步日志记录，支持多级别、
 * 多目标的日志输出，是可观测性基础设施的核心组件。
 */
namespace ngx::trace
{
    /**
     * @struct config
     * @brief 日志配置参数
     * @details 配置 spdlog 日志系统的各项参数，包括文件输出、
     * 控制台输出、日志轮转和异步队列等。所有字符串字段使用
     * memory::string 类型，配合 PMR 分配器减少堆碎片。
     * @note 线程安全的配置，可在运行时动态调整部分参数。
     */
    struct config
    {
        // 日志文件名，默认值为 "forward.log"
        memory::string file_name = "forward.log";

        // 日志文件存储路径，支持相对路径和绝对路径
        memory::string path_name = "logs";

        // 日志文件最大大小，默认 64MB，超过此大小触发文件滚动
        std::uint64_t max_size = 64ULL * 1024ULL * 1024ULL;

        // 日志文件最大数量，默认保留最近 8 个文件
        std::uint32_t max_files = 8U;

        // 日志队列大小，默认 8192 条，队列满时可能阻塞或丢弃日志
        std::uint32_t queue_size = 8192U;

        // 后台刷盘线程数，默认 1 个
        std::uint32_t thread_count = 1U;

        // 是否启用控制台输出，默认启用
        bool enable_console = true;

        // 是否启用文件输出，默认启用
        bool enable_file = true;

        // 日志级别，默认 "info"，可设置 trace/debug/info/warn/error/critical
        memory::string log_level = "info";

        // 日志格式，默认 "[%Y-%m-%d %H:%M:%S.%e][%l] %v"
        memory::string pattern = "[%Y-%m-%d %H:%M:%S.%e][%l] %v";

        // 日志追踪名称，默认 "forward_engine"
        memory::string trace_name = "forward_engine";
    };
}
