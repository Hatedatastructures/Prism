/**
 * @file routing.hpp
 * @brief 路由模块
 * @details 高性能路由匹配，使用编译期哈希和 string_view 实现零拷贝。
 *
 * 核心特性：
 * - 编译期哈希：使用 consteval FNV-1a 哈希实现 O(1) 路由查找
 * - 零拷贝：使用 string_view 避免字符串拷贝
 * - switch 优化：利用编译器 switch-case 优化
 *
 * C++23 特性：
 * - consteval：编译期强制计算
 * - if consteval：编译期条件分支
 * - std::unreachable()：标记不可达代码
 *
 * @note 设计原则：
 * - 简单数据载体：仅存储路由信息
 * - 零开销抽象：无虚函数开销
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <utility>
#include <bit>

namespace srv::routing
{
    /**
     * @brief FNV-1a 哈希算法（编译期强制计算）
     */
    consteval std::uint64_t fnv1a_hash(std::string_view str) noexcept
    {
        std::uint64_t hash = 14695981039346656037ULL;
        for (char c : str)
        {
            hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(c));
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    /**
     * @brief 运行时 FNV-1a 哈希（用于动态路由）
     */
    [[nodiscard]] inline std::uint64_t fnv1a_hash_runtime(std::string_view str) noexcept
    {
        std::uint64_t hash = 14695981039346656037ULL;
        for (char c : str)
        {
            hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(c));
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    /**
     * @enum route_type
     * @brief 路由类型枚举
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
     */
    struct route_result final
    {
        route_type type{route_type::not_found};
        std::string_view path{};
        std::string_view param{};
    };

    // 编译期计算的路由哈希值
    inline constexpr std::uint64_t hash_api_products = fnv1a_hash("/api/products");
    inline constexpr std::uint64_t hash_api_login = fnv1a_hash("/api/login");
    inline constexpr std::uint64_t hash_api_register = fnv1a_hash("/api/register");
    inline constexpr std::uint64_t hash_api_cart = fnv1a_hash("/api/cart");
    inline constexpr std::uint64_t hash_api_user = fnv1a_hash("/api/user");
    inline constexpr std::uint64_t hash_api_search = fnv1a_hash("/api/search");
    inline constexpr std::uint64_t hash_api_orders = fnv1a_hash("/api/orders");
    inline constexpr std::uint64_t hash_api_cart_item = fnv1a_hash("/api/cart/item");
    inline constexpr std::uint64_t hash_api_cart_items = fnv1a_hash("/api/cart/items");
    inline constexpr std::uint64_t hash_api_cart_checkout = fnv1a_hash("/api/cart/checkout");
    inline constexpr std::uint64_t hash_api_captcha_send = fnv1a_hash("/api/captcha/send");

    // 统计端口路由哈希
    inline constexpr std::uint64_t hash_ws_stats = fnv1a_hash("/ws/stats");
    inline constexpr std::uint64_t hash_api_stats = fnv1a_hash("/api/stats");
    inline constexpr std::uint64_t hash_api_stats_realtime = fnv1a_hash("/api/stats/realtime");
    inline constexpr std::uint64_t hash_api_connections = fnv1a_hash("/api/connections");
    inline constexpr std::uint64_t hash_api_connections_active = fnv1a_hash("/api/connections/active");
    inline constexpr std::uint64_t hash_api_performance = fnv1a_hash("/api/performance");

    /**
     * @class main_router
     * @brief 主端口路由器
     * @details 高性能路由匹配，使用编译期哈希 + switch 实现快速查找
     */
    class main_router final
    {
    public:
        [[nodiscard]] route_result match(std::string_view target) const noexcept
        {
            // 快速路径：静态文件（大多数请求）
            if (target.empty() || target[0] != '/')
            {
                return {route_type::static_file, target, {}};
            }

            // 检查是否是 API 路由
            if (!target.starts_with("/api/"))
            {
                return {route_type::static_file, target, {}};
            }

            // 动态路由检查（带参数的路由）
            if (target.starts_with("/api/product/"))
            {
                return {route_type::api_endpoint, "/api/product", target.substr(13)};
            }
            if (target.starts_with("/api/cart/") && target.size() > 10)
            {
                // 排除精确子路径，只匹配 /api/cart/<id> 格式
                // /api/cart/item, /api/cart/items, /api/cart/checkout 应该由精确匹配处理
                if (target != "/api/cart/item" &&
                    target != "/api/cart/items" &&
                    target != "/api/cart/checkout")
                {
                    return {route_type::api_endpoint, "/api/cart", target.substr(10)};
                }
            }
            if (target.starts_with("/api/orders/"))
            {
                return {route_type::api_endpoint, "/api/orders", target.substr(12)};
            }

            // 精确匹配：使用编译期哈希 + switch 优化
            const auto hash = fnv1a_hash_runtime(target);
            switch (hash)
            {
            case hash_api_products:
                return {route_type::api_endpoint, target, {}};
            case hash_api_login:
                return {route_type::api_endpoint, target, {}};
            case hash_api_register:
                return {route_type::api_endpoint, target, {}};
            case hash_api_cart:
                return {route_type::api_endpoint, target, {}};
            case hash_api_user:
                return {route_type::api_endpoint, target, {}};
            case hash_api_search:
                return {route_type::api_endpoint, target, {}};
            case hash_api_orders:
                return {route_type::api_endpoint, target, {}};
            case hash_api_cart_item:
                return {route_type::api_endpoint, target, {}};
            case hash_api_cart_items:
                return {route_type::api_endpoint, target, {}};
            case hash_api_cart_checkout:
                return {route_type::api_endpoint, target, {}};
            case hash_api_captcha_send:
                return {route_type::api_endpoint, target, {}};
            default:
                return {route_type::static_file, target, {}};
            }
        }
    };

    /**
     * @class stats_router
     * @brief 统计端口路由器
     */
    class stats_router final
    {
    public:
        [[nodiscard]] route_result match(std::string_view target) const noexcept
        {
            // 动态路由检查
            if (target.starts_with("/api/stats/history/"))
            {
                return {route_type::api_endpoint, "/api/stats/history", target.substr(19)};
            }

            // 精确匹配：使用编译期哈希 + switch 优化
            const auto hash = fnv1a_hash_runtime(target);
            switch (hash)
            {
            case hash_ws_stats:
                return {route_type::websocket_endpoint, target, {}};
            case hash_api_stats:
                return {route_type::api_endpoint, target, {}};
            case hash_api_stats_realtime:
                return {route_type::api_endpoint, target, {}};
            case hash_api_connections:
                return {route_type::api_endpoint, target, {}};
            case hash_api_connections_active:
                return {route_type::api_endpoint, target, {}};
            case hash_api_performance:
                return {route_type::api_endpoint, target, {}};
            default:
                return {route_type::static_file, target, {}};
            }
        }
    };
}
