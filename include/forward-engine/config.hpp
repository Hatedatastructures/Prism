/**
 * @file config.hpp
 * @brief 系统全局配置定义
 * @details 定义 ForwardEngine 系统的全局配置结构，采用聚合设计模式将
 * 各子系统的独立配置组合为统一的顶层配置。配置结构采用强类型设计，
 * 确保编译期类型安全。所有配置字段均为公开成员，便于序列化框架
 * 进行反射操作。
 */
#pragma once

#include <forward-engine/agent/config.hpp>
#include <forward-engine/trace/config.hpp>

namespace ngx
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

} // namespace ngx
