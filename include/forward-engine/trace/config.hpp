/**
 * @file config.hpp
 * @brief 日志系统配置
 * @details 定义了 `spdlog` 日志系统的配置参数，包括输出目标、格式、级别和性能调优选项。
 * 作为 `ForwardEngine` 可观测性系统的核心配置，支持高性能异步日志记录、日志轮转和多目标输出。
 *
 * 设计原理：
 * - 性能优先：使用异步日志记录，避免 `I/O` 操作阻塞业务线程；
 * - 配置驱动：通过配置结构灵活控制日志行为，支持热重载；
 * - 资源管理：控制日志文件大小和数量，避免磁盘空间耗尽；
 * - `PMR` 内存管理：使用 `memory::string`（`PMR` 分配器）减少堆碎片。
 *
 * 核心功能：
 * - 多目标输出：支持文件和控制台双输出，可独立启用/禁用；
 * - 日志轮转：基于文件大小和数量的自动轮转机制；
 * - 异步缓冲：后台线程刷盘，避免阻塞主业务逻辑；
 * - 格式定制：可自定义日志格式，支持时间戳、级别、线程 `ID` 等信息。
 *
 * 性能考虑：
 * - 异步队列大小（`queue_size`）影响内存使用和日志丢弃策略；
 * - 后台线程数（`thread_count`）影响 `I/O` 并发能力；
 * - 日志级别过滤在日志记录前完成，避免不必要的格式化和 `I/O`。
 *
 * 使用场景：
 * - 系统启动时从配置文件加载日志配置；
 * - 运行时动态调整日志级别，便于问题排查；
 * - 生产环境启用文件日志，开发环境启用控制台日志。
 *
 * @note 配置字段使用 `memory::string` 而非 `std::string`，减少堆分配和碎片。
 * @warning 异步日志队列满时，根据 `spdlog` 策略可能阻塞或丢弃日志，需合理设置 `queue_size`。
 * @warning 日志文件路径应有写权限，否则日志记录会失败。
 * @see spdlog 日志库文档
 *
 */
#pragma once

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
