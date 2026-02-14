/**
 * @file configuration.hpp
 * @brief 系统全局配置
 * @details 定义了 `ForwardEngine` 系统的全局配置结构，聚合代理服务和日志追踪配置。
 *
 * 设计原理：
 * - 配置聚合：将分散的子系统配置聚合为统一的结构，简化配置管理和传递；
 * - 类型安全：使用强类型结构体而非键值对，确保配置值的类型安全；
 * - 模块化设计：每个子系统维护独立的配置结构，顶层配置进行组合。
 *
 * 包含内容：
 * - 代理配置：`forward-engine/agent/config.hpp` - `Agent` 服务的工作线程数、连接池大小、超时设置等；
 * - 追踪配置：`forward-engine/trace/config.hpp` - 日志级别、输出格式、采样率、监控指标等。
 *
 * 使用场景：
 * - 系统启动时从配置文件或命令行参数加载全局配置；
 * - 各个子系统通过引用全局配置获取自己的配置参数；
 * - 配置热重载时更新全局配置并通知相关子系统。
 *
 * 性能考虑：
 * - 配置结构通常仅在初始化时加载，对运行时性能无影响；
 * - 配置值应使用值语义传递，避免动态分配和间接访问；
 * - 配置热重载应避免锁竞争，使用原子操作或无锁结构。
 */
#pragma once

#include <forward-engine/agent/config.hpp>
#include <forward-engine/trace/config.hpp>

namespace ngx::core
{
    /**
     * @struct configuration
     * @brief 全局配置结构
     * @details 聚合了 `ForwardEngine` 系统所有子系统的配置信息，提供统一的配置管理接口。
     *
     * 字段说明：
     * @details - `agent::config agent`：代理服务配置，包含工作线程数、连接池大小、超时设置等；
     * @details - `trace::config trace`：日志追踪配置，包含日志级别、输出格式、采样率、监控指标等。
     *
     *
     * 使用示例：
     * ```
     * // 构造默认配置
     * ngx::core::configuration config;
     *
     * // 修改配置参数
     * config.agent.worker_count = 8;
     * config.agent.connection_timeout = std::chrono::seconds(60);
     * config.trace.log_level = spdlog::level::debug;
     *
     * // 序列化为 JSON
     * std::string json = ngx::transformer::json::serialize(config);
     *
     * // 从 JSON 反序列化
     * auto parsed = ngx::transformer::json::deserialize<ngx::core::configuration>(json);
     * ```
     *
     * @note 配置字段应使用 `public` 访问权限，简化序列化和反射实现。
     * @warning 配置结构应保持 `POD`（普通旧数据）特性，避免包含复杂类型或动态分配。
     * @warning 配置热重载时应注意线程安全性，避免数据竞争。
     *
     */
    struct configuration
    {
        agent::config agent; ///< 代理服务配置
        trace::config trace; ///< 日志追踪配置
    };
}