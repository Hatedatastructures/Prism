#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>


namespace ngx::trace
{

    class  blacklist
    {
    public:
        // 默认构造
        blacklist() = default;

        // 1. 加载数据
        // 通常在程序启动或热加载时调用
        void load(const std::vector<std::string> &ips, const std::vector<std::string> &domains);


        bool endpoint(std::string_view endpoint_value) const;

        // 3. 检查域名 (支持子域名后缀匹配)
        // 例如：黑名单有 "baidu.com"，那么 "map.baidu.com" 也会被屏蔽
        bool domain(std::string_view host_value) const;

        void insert_domain(std::string_view domain);

        void insert_endpoint(std::string& endpoint_value);
        void clear();

    private:
        std::unordered_set<std::string> ips_;
        std::unordered_set<std::string> domains_;
    };

}