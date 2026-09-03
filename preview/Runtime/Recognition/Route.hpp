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
#include <preview/Runtime/Recognition/Protocol.hpp>

namespace Preview::Recognition
{

    /**
     * @struct RouteEntry
     * @brief SNI 路由目标
     * @details scheme 负责外层伪装包装；Protocol 为包装后的内层协议。
     *          AllowFallback 仅表示显式允许未命中方案时走回退路径。
     */
    struct RouteEntry
    {
        std::string Scheme;
        ProtocolType Protocol{ProtocolType::Unknown};
        bool AllowFallback{false};
    };

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
         * @param Domain 域名（支持 *. 前缀通配）
         * @param Scheme 方案名
         */
        void Add(std::string_view Domain, std::string_view Scheme)
        {
            Add(Domain, Scheme, ProtocolType::Unknown, false);
        }

        /**
         * @brief 添加带内层协议的路由
         * @param Domain 域名（支持 *. 前缀通配）
         * @param Scheme 方案名
         * @param Protocol 包装后的内层协议
         * @param AllowFallback 是否允许显式回退
         */
        void Add(std::string_view Domain, std::string_view Scheme, ProtocolType Protocol,
                 bool AllowFallback = false)
        {
            Routes_[Normalize(Domain)] = RouteEntry{std::string(Scheme), Protocol, AllowFallback};
        }

        /**
         * @brief 查询 SNI 对应方案
         * @param Sni SNI 域名
         * @return 方案名；未命中返回空
         * @details 先精确匹配，再选择最长的单标签通配项。
         */
        [[nodiscard]] auto Lookup(std::string_view Sni) const -> std::string_view
        {
            const auto *Entry = LookupEntry(Sni);
            return Entry ? std::string_view(Entry->Scheme) : std::string_view{};
        }

        /**
         * @brief 查询完整 SNI 路由
         * @param Sni SNI 域名
         * @return 路由条目；未命中返回 nullptr
         */
        [[nodiscard]] auto LookupEntry(std::string_view Sni) const -> const RouteEntry *
        {
            const auto Normalized = Normalize(Sni);
            if (const auto It = Routes_.find(Normalized); It != Routes_.end())
            {
                return &It->second;
            }

            // 通配匹配：只允许一个非空标签，并选择最长后缀。
            const RouteEntry *Best = nullptr;
            std::size_t BestSuffix = 0;
            for (const auto &[domain, scheme] : Routes_)
            {
                if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.')
                {
                    const std::string_view suffix(domain.data() + 1, domain.size() - 1);
                    if (Normalized.size() <= suffix.size() ||
                        !std::string_view(Normalized).ends_with(suffix))
                    {
                        continue;
                    }
                    const auto Prefix = std::string_view(Normalized).substr(
                        0, Normalized.size() - suffix.size());
                    if (Prefix.empty() || Prefix.find('.') != std::string_view::npos)
                    {
                        continue;
                    }
                    if (suffix.size() > BestSuffix)
                    {
                        BestSuffix = suffix.size();
                        Best = &scheme;
                    }
                }
            }
            return Best;
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
        [[nodiscard]] static auto Normalize(std::string_view Domain) -> std::string
        {
            std::string Result;
            Result.reserve(Domain.size());
            for (const auto Character : Domain)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                Result.push_back(static_cast<char>(Byte >= 'A' && Byte <= 'Z' ? Byte + ('a' - 'A') : Byte));
            }
            while (!Result.empty() && Result.back() == '.')
            {
                Result.pop_back();
            }
            return Result;
        }

        std::unordered_map<std::string, RouteEntry> Routes_;
    };

} // namespace Preview::Recognition
