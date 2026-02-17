/**
 * @file route.hpp
 * @brief 路由类型定义
 * @details 定义了路由类型枚举和路由结果结构体。
 *
 * 核心特性：
 * - 路由类型：区分静态文件、API、WebSocket 等不同类型的路由
 * - 路由结果：包含路由类型、处理函数、文件路径等信息
 *
 * @note 设计原则：
 * - 简单数据载体：仅存储路由信息，不包含业务逻辑
 * - 零开销抽象：使用枚举和结构体，无虚函数开销
 *
 */
#pragma once

#include <cstdint>
#include <functional>
#include <string_view>

namespace srv::router
{
    /**
     * @enum route_type
     * @brief 路由类型枚举
     * @details 定义了不同类型的路由
     */
    enum class route_type : std::uint8_t
    {
        static_file,
        api_endpoint,
        websocket_endpoint,
        not_found
    };

    /**
     * @struct route_result
     * @brief 路由结果结构体
     * @details 存储路由匹配的结果信息
     */
    struct route_result final
    {
        route_type type{route_type::not_found};
        std::string_view path{};
        std::string_view param{};
    };
}
