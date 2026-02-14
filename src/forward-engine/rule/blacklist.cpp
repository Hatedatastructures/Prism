#include <forward-engine/rule/blacklist.hpp>
#include <algorithm>


namespace ngx::rule
{
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

    auto blacklist::endpoint(const std::string_view endpoint_value) const
        -> bool
    {
        if (ips_.empty())
            return false;
        // string_view 转 string 可能会有分配，但在 set find 中 C++20 支持异构查找
        return ips_.find(endpoint_value) != ips_.end();
    }

    auto blacklist::domain(const std::string_view host_value) const
        -> bool
    {
        if (domains_.empty())
            return false;

        // 将输入转换为小写，避免每次查找时重复分配
        std::string lower(host_value);
        std::ranges::transform(lower, lower.begin(), ::tolower);

        std::string_view view = lower;
        while (true)
        {
            // 透明查找，避免构造临时 std::string
            if (domains_.find(view) != domains_.end())
            {
                return true;
            }

            const auto pos = view.find('.');
            if (pos == std::string_view::npos)
            {
                break;
            }
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

    void blacklist::clear()
    {
        ips_.clear();
        domains_.clear();
    }
}
