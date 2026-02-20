/**
 * @file routing.hpp
 * @brief 路由模块
 * @details 提供请求路由功能，将请求路径映射到相应的处理器。
 *
 * 核心特性：
 * - 路由类型：区分静态文件、API、WebSocket 等不同类型的路由
 * - 动态路由：支持 /api/product/:id、/api/cart/:id 等动态参数
 * - 零开销抽象：使用 string_view 避免字符串拷贝
 * - 高效匹配：使用 starts_with 和 == 等高效操作
 *
 * @note 设计原则：
 * - 简单数据载体：仅存储路由信息，不包含业务逻辑
 * - 零开销抽象：使用枚举和结构体，无虚函数开销
 *
 * @see httpsession.hpp
 */
#pragma once

#include <cstdint>
#include <string_view>

namespace srv::routing
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
     * @details 存储路由匹配的结果信息，包括路由类型、路径和动态参数
     */
    struct route_result final
    {
        /// @brief 路由类型（静态文件、API 端点、WebSocket 端点或未找到）
        route_type type{route_type::not_found};
        /// @brief 匹配的路由路径（对于动态路由为模板路径）
        std::string_view path{};
        /// @brief 从动态路由中提取的参数值（如 /api/product/:id 中的 id 值）
        std::string_view param{};
    };

    /**
     * @class main_router
     * @brief 主端口路由器类
     * @details 负责将请求路径路由到相应的处理器，支持动态路由
     *
     * 支持的路由：
     * - /api/products - 商品列表
     * - /api/product/:id - 商品详情
     * - /api/cart - 购物车
     * - /api/search - 商品搜索
     * - /api/user - 用户信息
     * - /api/cart/item - 购物车商品操作
     * - /api/cart/items - 购物车批量操作
     * - /api/cart/checkout - 购物车结算
     * - /api/orders - 订单操作
     * - /api/login - 用户登录
     * - /api/register - 用户注册
     * - /api/captcha/send - 发送验证码
     */
    class main_router final
    {
    public:
        /**
         * @brief 匹配请求路径
         * @param target 请求目标路径
         * @return 路由结果
         */
        [[nodiscard]] route_result match(std::string_view target) const noexcept
        {
            if (target == "/api/login")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/register")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/captcha/send")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

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

            if (target == "/api/cart/item")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/cart/items")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target == "/api/cart/checkout")
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

            if (target == "/api/orders")
            {
                return route_result{route_type::api_endpoint, target, ""};
            }

            if (target.starts_with("/api/orders/"))
            {
                return route_result{route_type::api_endpoint, "/api/orders", target.substr(12)};
            }

            return route_result{route_type::static_file, target, ""};
        }
    };

    /**
     * @class stats_router
     * @brief 统计端口路由器类
     * @details 负责将统计相关请求路径路由到相应的处理器
     *
     * 支持的路由：
     * - /ws/stats - WebSocket 实时统计
     * - /api/stats - 统计信息
     * - /api/stats/realtime - 实时统计
     * - /api/stats/history/:minutes - 历史统计
     * - /api/connections - 连接列表
     * - /api/performance - 性能指标
     */
    class stats_router final
    {
    public:
        /**
         * @brief 匹配请求路径
         * @param target 请求目标路径
         * @return 路由结果
         */
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

            return route_result{route_type::static_file, target, ""};
        }
    };
}
