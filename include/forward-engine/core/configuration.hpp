/**
 * @file configuration.hpp
 * @brief 系统全局配置定义
 * @details 该文件定义了 ForwardEngine 系统的全局配置结构，采用聚合
 * 设计模式将各子系统的独立配置组合为统一的顶层配置。这种设计使得
 * 配置管理更加集中和便捷，同时保持了各子系统配置的独立性和可维护
 * 性。配置结构采用强类型设计，确保编译期类型安全，避免运行时类型
 * 错误。所有配置字段均为公开成员，便于序列化框架进行反射操作。
 */
#pragma once

#include <forward-engine/agent/config.hpp>
#include <forward-engine/trace/config.hpp>

/**
 * @namespace ngx::core
 * @brief 核心配置模块命名空间
 * @details 该命名空间封装了系统的全局配置定义，作为配置管理的核心
 * 聚合层。通过将配置结构置于独立命名空间，既避免了全局命名污染，
 * 又为配置相关的类型和工具函数提供了逻辑分组。
 */
namespace ngx::core
{
    /**
     * @struct configuration
     * @brief 全局配置聚合结构体
     * @details 该结构体聚合了 ForwardEngine 系统所有子系统的配置项，
     * 提供统一的配置访问入口。采用结构体而非类的设计，使配置数据保持
     * POD 特性，便于 JSON 序列化、反序列化及反射操作。各子系统配置
     * 保持独立定义，顶层配置仅负责组合，遵循单一职责原则。
     * @note 配置结构应在程序初始化阶段完成加载，避免运行时频繁修改。
     * @warning 若需支持配置热重载，必须确保配置访问的线程安全性，
     * 建议采用读写锁或原子指针交换机制。
     * @throws 无异常抛出，配置结构为纯数据载体。
     */
    struct configuration
    {
        agent::config agent;  // 代理服务配置，含线程数、连接池、超时等
        trace::config trace;  // 日志追踪配置，含日志级别、格式、采样率等
    };
}
