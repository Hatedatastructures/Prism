#include <rule/blacklist.hpp>
#include <algorithm>


namespace ngx::rule
{
    /**
     * @brief  加载黑名单
     * @details 加载 ip 端点和域名到黑名单中
     * @param ips 要加载的 ip 端点列表
     * @param domains 要加载的域名列表
     */
    void blacklist::load(const std::vector<std::string> &ips,const std::vector<std::string> &domains)
    {

        ips_.clear();
        for (const auto &ip : ips)
        {
            ips_.insert(ip);
        }

        domains_.clear();
        for (const auto &domain : domains)
        {
            // 存入时统一转小写，方便后续不区分大小写比较
            std::string d = domain;
            std::ranges::transform(d, d.begin(), ::tolower);
            domains_.insert(d);
        }
    }

    /**
     * @brief  检查 ip 端点在不在黑名单
     * @param endpoint_value 要检测的ip端点
     * @return `true` 端点在黑名单 `false` 端点不在黑名单
     */
    bool blacklist::endpoint(const std::string_view endpoint_value) const
    {
        if (ips_.empty())
            return false;
        // string_view 转 string 可能会有分配，但在 set find 中 C++20 支持异构查找
        return ips_.contains(std::string(endpoint_value));
    }

    bool blacklist::domain(const std::string_view host_value) const
    {
        if (domains_.empty())
            return false;

        std::string domain(host_value);
        std::ranges::transform(domain, domain.begin(), ::tolower);

        // 策略：从后往前剥离域名进行匹配
        // map.baidu.com -> 查 "map.baidu.com"
        //               -> 查 "baidu.com" (命中!)
        //               -> 查 "com"

        std::string_view view = domain;
        while (true)
        {
            // C++20 contains
            if (domains_.contains(std::string(view)))
            {
                return true;
            }

            // 找下一个点号
            const auto pos = view.find('.');
            if (pos == std::string_view::npos)
            {
                break;
            }
            // 移动 view 到下一个子段，例如 "map.baidu.com" -> "baidu.com"
            view.remove_prefix(pos + 1);
        }

        return false;
    }
    void blacklist::insert_endpoint(std::string& endpoint_value)
    {
        ips_.emplace(endpoint_value);
    }

    void blacklist::insert_domain(const std::string_view domain)
    {
        std::string d(domain);
        // 强制转小写，确保匹配时不区分大小写
        std::ranges::transform(d, d.begin(), ::tolower);
        domains_.emplace(std::move(d));
    }

    /**
     * @brief  清空黑名单
     * @details 清空黑名单中的所有 ip 端点和域名
     */
    void blacklist::clear()
    {
        ips_.clear();
        domains_.clear();
    }
}
