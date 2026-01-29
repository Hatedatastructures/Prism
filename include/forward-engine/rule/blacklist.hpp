/**
 * @file blacklist.hpp
 * @brief 黑名单管理
 * @details 提供基于 IP 和域名的黑名单匹配功能，支持精确 IP 匹配和域名后缀匹配。
 */
#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>


namespace ngx::rule
{
    /**
     * @brief 黑名单类
     * @details 管理 IP 和域名的黑名单，提供快速查询接口。
     */
    class blacklist
    {
    public:
        /**
         * @brief 默认构造函数
         */
        blacklist() = default;

        /**
         * @brief 加载黑名单数据
         * @param ips IP 黑名单列表
         * @param domains 域名黑名单列表
         * @details 通常在程序启动或热加载时调用。
         */
        void load(const std::vector<std::string> &ips, const std::vector<std::string> &domains);

        /**
         * @brief 检查端点（IP）是否在黑名单中
         * @param endpoint_value 待检查的 IP 地址字符串
         * @return true 如果在黑名单中，false 否则
         */
        bool endpoint(std::string_view endpoint_value) const;

        /**
         * @brief 检查域名是否在黑名单中
         * @param host_value 待检查的域名
         * @return true 如果域名或其后缀在黑名单中，false 否则
         * @details 支持子域名后缀匹配。例如：黑名单有 "baidu.com"，那么 "map.baidu.com" 也会被屏蔽。
         */
        bool domain(std::string_view host_value) const;

        /**
         * @brief 插入单个域名到黑名单
         * @param domain 待插入的域名
         */
        void insert_domain(std::string_view domain);

        /**
         * @brief 插入单个端点（IP）到黑名单
         * @param endpoint_value 待插入的 IP 地址
         */
        void insert_endpoint(std::string& endpoint_value);

        /**
         * @brief 清空黑名单
         */
        void clear();

    private:
        std::unordered_set<std::string> ips_;     // IP 黑名单集合
        std::unordered_set<std::string> domains_; // 域名黑名单集合
    };

}