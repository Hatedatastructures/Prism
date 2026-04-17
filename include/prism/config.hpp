/**
 * @file config.hpp
 * @brief Config 模块聚合头文件
 * @details 聚合引入系统全局配置定义，将各子系统的独立配置
 * 组合为统一的顶层配置。包含代理服务配置和日志追踪配置
 * 两个子模块的聚合入口。配置结构采用强类型设计，确保
 * 编译期类型安全，所有字段均为公开成员便于序列化。
 */
#pragma once

#include <prism/agent/config.hpp>
#include <prism/trace/config.hpp>

namespace psm
{
    /**
     * @struct config
     * @brief 全局配置聚合结构体
     * @details 聚合所有子系统的配置项，提供统一的配置访问入口。
     * 各子系统配置保持独立定义，顶层配置仅负责组合。
     * @note 配置应在程序初始化阶段完成加载，避免运行时频繁修改。
     */
    struct config
    {
        agent::config agent; // 代理服务配置
        trace::config trace; // 日志追踪配置
    };

} // namespace psm
