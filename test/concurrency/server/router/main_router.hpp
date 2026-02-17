/**
 * @file main_router.hpp
 * @brief 主端口路由器定义
 * @details 负责将请求路径路由到相应的处理器，支持动态路由。
 *
 * 核心特性：
 * - API 路由：支持 /api/products、/api/cart、/api/search 等
 * - 动态路由：支持 /api/product/:id、/api/cart/:id 等动态参数
 * - 静态文件：默认路由到静态文件服务
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
     * @class main_router
     * @brief 主端口路由器类
     * @details 负责将请求路径路由到相应的处理器，支持动态路由
     */
    class main_router final
    {
    public:
        [[nodiscard]] route_result match(std::string_view target) const noexcept
        {
            if (target == "/api/products")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target.starts_with("/api/product/"))
            {
                return route_result{route_type::api_endpoint, "/api/product", target.substr(13)};
            }

            if (target == "/api/cart")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target.starts_with("/api/cart/"))
            {
                return route_result{route_type::api_endpoint, "/api/cart", target.substr(10)};
            }

            if (target == "/api/search")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/user")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            return route_result{route_type::static_file, target, ""};
        }
    };
}
