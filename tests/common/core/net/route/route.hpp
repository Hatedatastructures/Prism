/**
 * @file route.hpp
 * @brief 出站路由表（positive/reverse）
 * @details 目标 host 路由：
 *          - reverse_map：域名 → 固定端点（反向代理）
 *          - positive：默认正向端点
 *          查找 O(1)（哈希），无临时分配（string_view 键）。
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace psmtest::net_route
{

    /**
     * @struct endpoint
     * @brief 目标端点
     */
    struct endpoint
    {
        std::string host;    ///< 主机（IP 或域名）
        std::uint16_t port{0}; ///< 端口
    };

    /**
     * @class route_table
     * @brief 出站路由表
     */
    class route_table
    {
    public:
        /**
         * @brief 添加反向路由（域名 → 端点）
         * @param host 域名键
         * @param ep 目标端点
         */
        void add_reverse(std::string_view host, endpoint ep)
        {
            reverse_[std::string(host)] = std::move(ep);
        }

        /**
         * @brief 设置正向端点
         * @param ep 正向端点（可空）
         */
        void set_positive(std::optional<endpoint> ep)
        {
            positive_ = std::move(ep);
        }

        /**
         * @brief 查询路由
         * @param host 目标域名
         * @return 路由端点；未命中返回 std::nullopt
         * @details 优先反向映射，其次正向端点。
         */
        [[nodiscard]] auto lookup(std::string_view host) const -> std::optional<endpoint>
        {
            if (const auto it = reverse_.find(std::string(host)); it != reverse_.end())
            {
                return it->second;
            }
            return positive_;
        }

        /**
         * @brief 是否命中反向映射
         * @param host 目标域名
         * @return 命中返回 true
         */
        [[nodiscard]] auto is_reverse(std::string_view host) const -> bool
        {
            return reverse_.contains(std::string(host));
        }

        /**
         * @brief 路由表大小
         * @return 反向条目数
         */
        [[nodiscard]] auto size() const noexcept -> std::size_t
        {
            return reverse_.size();
        }

        /**
         * @brief 清空路由表
         */
        void clear()
        {
            reverse_.clear();
            positive_.reset();
        }

    private:
        std::unordered_map<std::string, endpoint> reverse_; ///< 反向映射
        std::optional<endpoint> positive_;                  ///< 正向端点
    };

} // namespace psmtest::net_route
