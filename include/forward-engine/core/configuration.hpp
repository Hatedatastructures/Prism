/**
 * @file configuration.hpp
 * @brief 系统全局配置
 * @details 定义了包含代理服务配置和日志追踪配置的全局配置结构。
 */
#pragma once

#include <forward-engine/agent/config.hpp>
#include <forward-engine/trace/config.hpp>

namespace ngx::core
{
    /**
     * @brief 全局配置结构
     * @details 聚合了各个子系统的配置信息。
     */
    struct configuration 
    {
        agent::config agent; // 代理服务配置
        trace::config trace; // 日志追踪配置
    };
}