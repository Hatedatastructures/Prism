/**
 * @file config.hpp
 * @brief 日志系统配置
 * @details 定义 spdlog 日志系统的配置参数，支持异步
 * 日志记录、日志轮转和多目标输出。所有字符串字段
 * 使用 memory::string 类型，配合 PMR 分配器。
 * @warning 异步日志队列满时可能阻塞或丢弃日志，
 * 需合理设置 queue_size。
 */
#pragma once

#include <prism/memory/container.hpp>

namespace psm::trace
{
    /**
     * @struct config
     * @brief 日志配置参数
     * @details 配置 spdlog 日志系统的各项参数，包括
     * 文件输出、控制台输出、日志轮转和异步队列。
     */
    struct config
    {
        memory::string file_name = "prism.log";                 // 日志文件名
        memory::string path_name = "logs";                        // 日志文件存储路径
        std::uint64_t max_size = 64ULL * 1024ULL * 1024ULL;       // 文件最大大小，默认 64MB
        std::uint32_t max_files = 8U;                             // 最大文件数量
        std::uint32_t queue_size = 8192U;                         // 异步队列大小
        std::uint32_t thread_count = 1U;                          // 后台刷盘线程数
        bool enable_console = true;                               // 是否启用控制台输出
        bool enable_file = true;                                  // 是否启用文件输出
        memory::string log_level = "info";                        // 日志级别
        memory::string pattern = "[%Y-%m-%d %H:%M:%S.%e][%l] %v"; // 日志格式
        memory::string trace_name = "prism";             // 日志追踪名称
    }; // struct config
} // namespace psm::trace
