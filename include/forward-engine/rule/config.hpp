/**
 * @file config.hpp
 * @brief 规则配置结构
 * @details 定义规则模块的配置结构，用于配置规则引擎的行为参数。该模块为规则引擎提供可配置的选项，支持灵活的安全策略定制。
 *
 * 设计目标：
 * @details - 可扩展性：配置结构设计为可扩展，便于添加新的规则配置项；
 * @details - 热重载：支持运行时配置更新，无需重启服务；
 * @details - 类型安全：使用强类型配置项，避免配置错误。
 *
 * 配置项（预留）：
 * @details - 黑名单文件路径：指定黑名单数据文件的加载路径；
 * @details - 规则更新间隔：配置规则热重载的时间间隔；
 * @details - 匹配模式：配置域名匹配的精确度（精确匹配/后缀匹配）。
 *
 * @note 当前配置结构为空，预留用于未来扩展规则相关的配置项。
 * @warning 配置修改后需要重新加载才能生效。
 */
#pragma once

#include <string>
#include <cstdint>

namespace ngx::rule
{
    /**
     * @brief 规则配置结构体
     * @details 目前为空，预留用于未来扩展规则相关的配置项。
     */
    struct config
    {

    };
}