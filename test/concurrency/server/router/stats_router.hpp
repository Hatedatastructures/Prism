/**
 * @file stats_router.hpp
 * @brief 统计端口路由器定义
 * @details 负责将统计相关请求路径路由到相应的处理器。
 *
 * 核心特性：
 * - 统计 API：支持 /api/stats、/api/connections 等
 * - WebSocket：支持 /ws/stats 实时统计推送
 * - 动态路由：支持 /api/stats/history/:minutes 等动态参数
 *
 * @note 设计原则：
 * - 零开销抽象：使用 string_view 避免字符串拷贝
 * - 高效匹配：使用 starts_with 和 == 等高效操作
 *
 */
#pragma once

#include "route.hpp"

namespace srv::router
{
    /**
     * @class stats_router
     * @brief 统计端口路由器类
     * @details 负责将统计相关请求路径路由到相应的处理器
     */
    class stats_router final
    {
    public:
        [[nodiscard]] route_result match(std::string_view target) const noexcept
        {
            if (target == "/ws/stats")
            {
                return route_result{route_type::websocket_endpoint, target, ""};
            }

            if (target == "/api/stats")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/stats/realtime")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target.starts_with("/api/stats/history/"))
            {
                return route_result{route_type::api_endpoint, "/api/stats/history", target.substr(19)};
            }

            if (target == "/api/connections")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/connections/active")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/performance")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            return route_result{route_type::not_found, target, ""};
        }
    };
}
