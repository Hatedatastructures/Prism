/**
 * @file Route.hpp
 * @brief SNI 路由表（域名 → 伪装方案）
 * @details 供 stealth 方案识别：TLS ClientHello 的 SNI 域名查表
 *          决定执行哪个伪装方案。支持精确匹配与通配子域。
 */

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <preview/Foundation/Memory/Container.hpp>

namespace Preview::Recognition
{

    /**
     * @class SniRouteTable
     * @brief SNI 路由表
     * @details 域名 → 方案名映射。支持：
     *          - 精确匹配："example.com"
     *          - 通配匹配："*.example.com"（子域）
     */
    class SniRouteTable
    {
    public:
        /**
         * @brief 添加路由
         * @param domain 域名（支持 *. 前缀通配）
         * @param scheme 方案名
         */
        void Add(std::string_view domain, std::string_view scheme)
        {
            Routes_[std::string(domain)] = std::string(scheme);
        }

        /**
         * @brief 查询 SNI 对应方案
         * @param sni SNI 域名
         * @return 方案名；未命中返回空
         * @details 先精确匹配，再遍历通配项（后缀匹配）。
         */
        [[nodiscard]] auto Lookup(std::string_view sni) const -> std::string_view
        {
            if (const auto It = Routes_.find(std::string(sni)); It != Routes_.end())
            {
                return It->second;
            }
            // 通配匹配：*.Domain 命中 sni 的父域
            for (const auto &[domain, scheme] : Routes_)
            {
                if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.')
                {
                    const std::string_view suffix(domain.data() + 1, domain.size() - 1);
                    if (sni.size() > suffix.size() &&
                        sni.substr(sni.size() - suffix.size()) == suffix)
                    {
                        return scheme;
                    }
                }
            }
            return {};
        }

        /**
         * @brief 路由表大小
         * @return 条目数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Routes_.size();
        }

        /**
         * @brief 清空路由表
         */
        void Clear()
        {
            Routes_.clear();
        }

    private:
        std::unordered_map<std::string, std::string> Routes_;
    };

} // namespace Preview::Recognition
