#include <forward-engine/resolve/rules.hpp>

#include <algorithm>
#include <boost/asio.hpp>
#include <cctype>
#include <string>

namespace ngx::resolve
{

    auto domain_trie::to_lower(const std::string_view s) -> memory::string
    {
        // 使用默认内存资源（静态函数无法访问实例 mr_）
        memory::string result(s.size(), '\0');
        auto to_lower = [](const unsigned char ch)
        {
            return static_cast<char>(std::tolower(ch));
        };
        std::transform(s.begin(), s.end(), result.begin(), to_lower);
        return result;
    }

    auto domain_trie::split_labels(const std::string_view domain) -> memory::vector<memory::string>
    {
        // 默认分配器用于静态函数
        memory::vector<memory::string> labels;

        // 跳过前导和末尾的 '.'
        auto view = domain;
        while (!view.empty() && view.front() == '.')
        {
            view.remove_prefix(1);
        }
        while (!view.empty() && view.back() == '.')
        {
            view.remove_suffix(1);
        }

        if (view.empty())
        {
            return labels;
        }

        // 按 '.' 分割标签
        while (true)
        {
            const auto pos = view.find('.');
            if (pos == std::string_view::npos)
            {
                labels.emplace_back(to_lower(view));
                break;
            }
            labels.emplace_back(to_lower(view.substr(0, pos)));
            view.remove_prefix(pos + 1);
        }

        // 反转标签顺序: ["www", "example", "com"] → ["com", "example", "www"]
        std::reverse(labels.begin(), labels.end());

        return labels;
    }

    void domain_trie::insert(const std::string_view domain, const std::any &value)
    {
        if (domain.empty())
        {
            return;
        }

        // 检查是否为通配符规则（以 "*." 开头）
        const bool is_wildcard = domain.starts_with("*.");

        // 去掉通配符前缀和末尾 '.'
        auto cleaned = domain;
        if (is_wildcard)
        {
            cleaned.remove_prefix(2); // 去掉 "*."
        }
        while (!cleaned.empty() && cleaned.back() == '.')
        {
            cleaned.remove_suffix(1);
        }

        if (cleaned.empty())
        {
            return;
        }

        // 分割并反转标签
        auto labels = split_labels(cleaned);

        if (labels.empty())
        {
            return;
        }

        // 通配符规则: 在倒数第一个标签节点标记 wildcard
        // 例如 "*.example.com" → 标签 ["com", "example"]，在 "example" 节点标记 wildcard
        const auto wildcard_depth = is_wildcard ? labels.size() - 1 : 0;

        node *current = root_.get();
        for (std::size_t i = 0; i < labels.size(); ++i)
        {
            const auto &label = labels[i];

            // 在指定深度标记 wildcard
            if (is_wildcard && i == wildcard_depth)
            {
                current->wildcard = true;
            }

            // 查找或创建子节点
            auto it = current->children.find(label);
            if (it == current->children.end())
            {
                auto [inserted, success] = current->children.emplace(
                    label, std::make_unique<node>(mr_));
                it = inserted;
            }
            current = it->second.get();
        }

        // 最终节点设置值和结束标记
        current->value = value;
        current->is_end = true;
    }


    auto domain_trie::search(const std::string_view domain) const -> std::optional<std::any>
    {
        if (domain.empty())
        {
            return std::nullopt;
        }

        // 去掉末尾 '.'
        auto cleaned = domain;
        while (!cleaned.empty() && cleaned.back() == '.')
        {
            cleaned.remove_suffix(1);
        }

        auto labels = split_labels(cleaned);
        if (labels.empty())
        {
            return std::nullopt;
        }

        // 沿反转标签路径逐级遍历，记录沿途节点用于 wildcard 回溯
        // path[i] 对应第 i 级节点，path[0] 为 root_ 的子节点
        memory::vector<const node *> path(mr_);
        path.reserve(labels.size());

        const node *current = root_.get();
        for (std::size_t i = 0; i < labels.size(); ++i)
        {
            const auto it = current->children.find(labels[i]);
            if (it == current->children.end())
            {
                break;
            }
            current = it->second.get();
            path.push_back(current);
        }

        // 检查精确匹配: 遍历了所有标签且最终节点是规则终点
        if (path.size() == labels.size() && current->is_end)
        {
            return current->value;
        }

        // 回溯检查 wildcard: 从路径末端向前查找第一个 wildcard 节点
        // 通配符要求查询域名至少比通配符域名多一级标签
        for (auto idx = static_cast<std::ptrdiff_t>(path.size()) - 1; idx >= 0; --idx)
        {
            const node *candidate = path[static_cast<std::size_t>(idx)];
            if (candidate->wildcard && candidate->is_end)
            {
                // path.size() 是实际遍历深度，idx+1 是 wildcard 节点的深度
                // 查询域名至少要比通配符域名多一级
                if (labels.size() > static_cast<std::size_t>(idx + 1))
                {
                    return candidate->value;
                }
            }
        }

        return std::nullopt;
    }


    auto domain_trie::match(const std::string_view domain) const -> bool
    {
        return search(domain).has_value();
    }



    void rules_engine::add_address_rule(const std::string_view domain, const memory::vector<net::ip::address> &ips)
    {
        address_trie_.insert(domain, std::any(ips));
    }



    void rules_engine::add_negative_rule(const std::string_view domain)
    {
        // 使用空地址列表 + 负标记表示否定规则
        address_trie_.insert(domain, std::any(true));
    }



    void rules_engine::add_cname_rule(const std::string_view domain, const std::string_view target)
    {
        // 存储目标域名
        memory::string target_str(mr_);
        target_str.assign(target);
        cname_trie_.insert(domain, std::any(std::move(target_str)));
    }

    auto rules_engine::match(const std::string_view domain) const -> std::optional<rule_result>
    {
        // 在地址规则树中查找
        const auto addr_value = address_trie_.search(domain);
        // 在 CNAME 规则树中查找
        const auto cname_value = cname_trie_.search(domain);

        // 两个规则树均未命中
        if (!addr_value.has_value() && !cname_value.has_value())
        {
            return std::nullopt;
        }

        rule_result result(mr_);
        bool hit = false;

        if (addr_value.has_value())
        {
            // 尝试提取否定规则标记（bool）
            const auto *neg_ptr = std::any_cast<bool>(&addr_value.value());
            if (neg_ptr != nullptr && *neg_ptr)
            {
                // 否定规则: 标记为广告屏蔽和拦截
                result.negative = true;
                result.blocked = true;
                result.no_cache = true;
                hit = true;
            }
            else
            {
                // 尝试提取地址列表
                const auto *ips_ptr = std::any_cast<memory::vector<net::ip::address>>(&addr_value.value());
                if (ips_ptr != nullptr && !ips_ptr->empty())
                {
                    result.addresses = *ips_ptr;
                    hit = true;
                }
            }
        }

        if (cname_value.has_value())
        {
            // 尝试提取 CNAME 目标域名
            const auto *target_ptr = std::any_cast<memory::string>(&cname_value.value());
            if (target_ptr != nullptr && !target_ptr->empty())
            {
                result.cname = *target_ptr;
                hit = true;
            }
        }

        if (!hit)
        {
            return std::nullopt;
        }

        return result;
    }
} // namespace ngx::resolve
