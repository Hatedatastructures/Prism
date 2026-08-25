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

namespace Preview::Network::Route
{

    /**
     * @struct Endpoint
     * @brief 目标端点
     */
    struct Endpoint
    {
        std::string Host;    ///< 主机（IP 或域名）
        std::uint16_t Port{0}; ///< 端口
    };

    /**
     * @class RouteTable
     * @brief 出站路由表
     */
    class RouteTable
    {
    public:
        /**
         * @brief 添加反向路由（域名 → 端点）
         * @param host 域名键
         * @param ep 目标端点
         */
        void AddReverse(std::string_view host, Endpoint ep)
        {
            reverse_[std::string(host)] = std::move(ep);
        }

        /**
         * @brief 设置正向端点
         * @param ep 正向端点（可空）
         */
        void SetPositive(std::optional<Endpoint> ep)
        {
            positive_ = std::move(ep);
        }

        /**
         * @brief 查询路由
         * @param host 目标域名
         * @return 路由端点；未命中返回 std::nullopt
         * @details 优先反向映射，其次正向端点。
         */
        [[nodiscard]] auto Lookup(std::string_view host) const -> std::optional<Endpoint>
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
        [[nodiscard]] auto IsReverse(std::string_view host) const -> bool
        {
            return reverse_.contains(std::string(host));
        }

        /**
         * @brief 路由表大小
         * @return 反向条目数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return reverse_.size();
        }

        /**
         * @brief 清空路由表
         */
        void Clear()
        {
            reverse_.clear();
            positive_.reset();
        }

    private:
        std::unordered_map<std::string, Endpoint> reverse_; ///< 反向映射
        std::optional<Endpoint> positive_;                  ///< 正向端点
    };

} // namespace Preview::Network::Route
