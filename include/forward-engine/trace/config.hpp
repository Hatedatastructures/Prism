/**
 * @file config.hpp
 * @brief 日志系统配置
 * @details 定义了 spdlog 日志系统的配置参数，包括输出目标、格式、级别和性能调优选项。
 */
#pragma once

#include <cstdint>
#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::trace
 * @brief 日志与可观测性系统
 * @details 负责系统的日志记录、性能监控和链路追踪。
 * 基于 spdlog 实现高性能的异步日志记录，支持多级别、多目标的日志输出。
 */
namespace ngx::trace
{
     /**
     * @brief 日志配置参数
     * @details 此结构体用于配置 `spdlog` 日志系统的各项参数。
     * @note 线程安全的配置，可在运行时动态调整部分参数。
     * @see 文档地址：https://github.com/gabime/spdlog.git
     */
    struct config
    {
        /**
         * @brief 日志文件名
         * @details 默认值为 "forward.log"。
         */
        memory::string file_name = "forward.log";

        /**
         * @brief 日志文件存储路径
         * @details 支持相对路径和绝对路径。如果为空，则使用当前目录。
         */        
        memory::string path_name = "logs";

        /**
         * @brief 日志文件最大大小
         * @details 默认值为 64MB。超过此大小将触发文件滚动。
         */
        std::uint64_t max_size = 64ULL * 1024ULL * 1024ULL;

        /**
         * @brief 日志文件最大数量
         * @details 默认保留最近的 8 个文件。
         */
        std::uint32_t max_files = 8U;
        
        /**
         * @brief 日志队列大小
         * @details 默认值为 8192 条日志消息。队列满时可能会阻塞或丢弃日志（取决于策略）。
         */
        std::uint32_t queue_size = 8192U;
        
        /**
         * @brief 日志线程数
         * @details 默认值为 1 个后台线程负责刷盘。
         */
        std::uint32_t thread_count = 1U;

        /**
         * @brief 是否启用控制台输出
         * @details 默认启用。
         */
        bool enable_console = true;

        /**
         * @brief 是否启用文件输出
         * @details 默认启用。
         */
        bool enable_file = true;

        /**
         * @brief 日志级别
         * @details 默认为 "info"。可设置为 "trace", "debug", "info", "warn", "error", "critical"。
         */
        memory::string log_level = "info";

        /**
         * @brief 日志格式
         * @details 默认值为 "[%Y-%m-%d %H:%M:%S.%e][%l] %v"。
         */
        memory::string pattern = "[%Y-%m-%d %H:%M:%S.%e][%l] %v";

        /**
         * @brief 日志追踪名称
         * @details 默认值为 "forward_engine"。
         */
        memory::string trace_name = "forward_engine";
    };
}
