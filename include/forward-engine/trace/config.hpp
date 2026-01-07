#pragma once

#include <string>
#include <cstdint>

namespace ngx::trace
{
     /**
     * @brief 日志追踪系统的配置参数结构体
     *
     * 此结构体用于配置 `spdlog` 日志系统的各项参数，包括文件输出、控制台输出、
     * 日志格式、级别等。所有配置都有合理地默认值。
     *
     * @note 线程安全的配置，可在运行时动态调整部分参数
     * @see 参考 spdlog 文档了解更多细节
     * 
     * @see 文档地址：https://github.com/gabime/spdlog.git
     */
    struct config
    {
        /**
         * @brief 日志文件名
         * @details 默认值为 "forward.log"
         */
        std::string file_name = "forward.log";

        /**
         * @brief 日志文件存储路径
         * @details 支持相对路径和绝对路径。如果为空，则使用当前目录
         */        
        std::string path_name = "logs";

        /**
         * @brief 日志文件最大大小
         * @details 默认值为 64MB
         */
        std::uint64_t max_size = 64ULL * 1024ULL * 1024ULL;

        /**
         * @brief 日志文件最大数量
         * @details 默认值为 8 个文件
         */
        std::uint32_t max_files = 8U;
        
        /**
         * @brief 日志队列大小
         * @details 默认值为 8192 条日志消息
         */
        std::uint32_t queue_size = 8192U;
        
        /**
         * @brief 日志线程数
         * @details 默认值为 1 个线程
         */
        std::uint32_t thread_count = 1U;

        /**
         * @brief 是否启用控制台输出
         * @details 默认值为 true
         */
        bool enable_console = true;

        /**
         * @brief 是否启用文件输出
         * @details 默认值为 true
         */
        bool enable_file = true;

        /**
         * @brief 日志级别
         * @details 默认 info 级别。可设置为 trace、debug、info、warn、error、critical
         */
        std::string log_level = "info";

        /**
         * @brief 日志格式
         * @details 默认值为 "[%Y-%m-%d %H:%M:%S.%e][%l] %v"
         */
        std::string pattern = "[%Y-%m-%d %H:%M:%S.%e][%l] %v";

        /**
         * @brief 日志追踪名称
         * @details 默认值为 "forward_engine"
         */
        std::string trace_name = "forward_engine";
    };
}
