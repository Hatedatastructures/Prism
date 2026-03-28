/**
 * @file recursor.cpp
 * @brief 高性能 DNS 解析器门面实现
 * @details 实现完整的查询管道：规则匹配 → 缓存查找 → 请求合并 →
 * 上游查询 → IP 过滤 → TTL 钳制 + 缓存存储。
 */

#include <algorithm>
#include <cctype>
#include <numeric>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <forward-engine/resolve/recursor.hpp>

namespace ngx::resolve
{
    recursor::recursor(net::io_context &ioc, config cfg, const memory::resource_pointer mr)
        : ioc_(ioc), mr_(mr ? mr : memory::current_resource()), config_(std::move(cfg)),
          upstream_(ioc_, mr_), cache_(mr_, config_.cache_ttl, config_.cache_size, config_.serve_stale),
          rules_(mr_),
          coalescer_(mr_)
    {
        // 初始化上游服务器和解析策略
        if (!config_.servers.empty())
        {
            upstream_.set_servers(std::move(config_.servers));
        }
        upstream_.set_mode(config_.mode);
        upstream_.set_timeout(config_.timeout_ms);

        // 加载域名规则
        for (const auto &rule : config_.address_rules)
        {
            if (rule.negative)
            {
                rules_.add_negative_rule(rule.domain);
            }
            else if (!rule.addresses.empty())
            {
                rules_.add_address_rule(rule.domain, rule.addresses);
            }
        }

        for (const auto &rule : config_.cname_rules)
        {
            rules_.add_cname_rule(rule.domain, rule.target);
        }
    }

    auto recursor::normalize(const std::string_view domain, const memory::resource_pointer mr) -> memory::string
    {
        memory::string result(domain, mr);
        // 转小写
        auto to_lower = [](const unsigned char ch)
        {
            return static_cast<char>(std::tolower(ch));
        };
        std::transform(result.begin(), result.end(), result.begin(), to_lower);
        // 去掉末尾点号
        while (!result.empty() && result.back() == '.')
        {
            result.pop_back();
        }
        return result;
    }

    auto recursor::is_blacklisted(const net::ip::address &ip) const -> bool
    {
        if (ip.is_v4())
        {
            const auto v4 = ip.to_v4();
            for (const auto &network : config_.blacklist_v4)
            {
                if (network.hosts().find(v4) != network.hosts().end())
                {
                    return true;
                }
            }
            return false;
        }

        if (ip.is_v6())
        {
            const auto v6 = ip.to_v6();
            for (const auto &network : config_.blacklist_v6)
            {
                if (network.hosts().find(v6) != network.hosts().end())
                {
                    return true;
                }
            }
            return false;
        }

        return false;
    }

    auto recursor::query_pipeline(const std::string_view domain, const qtype qt)
        -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>
    {
        // 规范化
        const auto qname = normalize(domain, mr_);

        // 1：规则匹配
        if (const auto rule = rules_.match(qname); rule)
        {
            if (rule->blocked)
            {
                trace::debug("[Resolve] {} blocked by rule", qname);
                co_return std::make_pair(fault::code::blocked, memory::vector<net::ip::address>(mr_));
            }
            if (rule->negative)
            {
                // 广告屏蔽：返回空列表 + 成功
                trace::debug("[Resolve] {} negative rule hit", qname);
                co_return std::make_pair(fault::code::success, memory::vector<net::ip::address>(mr_));
            }
            if (!rule->addresses.empty())
            { // 静态地址：返回规则指定的 IP 列表
                trace::debug("[Resolve] {} -> static address ({} IPs)", qname, rule->addresses.size());
                co_return std::make_pair(fault::code::success, memory::vector<net::ip::address>(rule->addresses));
            }
        }

        // 2：缓存查找
        if (config_.cache_enabled)
        {
            cache_.evict_expired();
            if (auto cached = cache_.get(qname, qt); cached)
            {
                if (cached->empty())
                {
                    trace::debug("[Resolve] {} negative cache hit", qname);
                    co_return std::make_pair(fault::code::dns_failed, std::move(*cached));
                }
                trace::debug("[Resolve] {} cache hit ({} IPs)", qname, cached->size());
                co_return std::make_pair(fault::code::success, std::move(*cached));
            }
        }

        // 3：请求合并
        coalescer_.flush_cleanup();

        const auto qt_str = std::to_string(static_cast<std::uint16_t>(qt));
        const auto key = coalescer_.make_key(qname, qt_str);
        const auto [flight_it, is_new] = coalescer_.find_or_create(key, ioc_.get_executor());

        if (!is_new)
        {
            // 已有相同查询在进行中，等待完成
            if (!flight_it->ready)
            {
                ++flight_it->waiters;
                boost::system::error_code ignored;
                co_await flight_it->timer.async_wait(net::redirect_error(net::use_awaitable, ignored));
                --flight_it->waiters;
            }

            // 等待完成后重新查找缓存
            coalescer::cleanup_flight(flight_it);

            if (config_.cache_enabled)
            {
                if (auto cached = cache_.get(qname, qt); cached)
                {
                    co_return std::make_pair(cached->empty() ? fault::code::dns_failed : fault::code::success, std::move(*cached));
                }
            }

            co_return std::make_pair(fault::code::dns_failed, memory::vector<net::ip::address>(mr_));
        }

        // 4：上游查询
        auto result = co_await upstream_.resolve(qname, qt);

        // 通知所有等待者
        flight_it->ready = true;
        flight_it->timer.cancel();
        coalescer::cleanup_flight(flight_it);

        // 5：IP 过滤（按查询类型过滤地址族 + 黑名单）
        if (succeeded(result.error) && !result.ips.empty())
        {
            memory::vector<net::ip::address> filtered(mr_);
            filtered.reserve(result.ips.size());
            const bool want_v4 = (qt == qtype::a);
            const bool want_v6 = (qt == qtype::aaaa);
            for (const auto &ip : result.ips)
            {
                if (!is_blacklisted(ip) && ip.is_v4() == want_v4 && ip.is_v6() == want_v6)
                {
                    filtered.push_back(ip);
                }
            }
            if (filtered.empty())
            {
                if (config_.cache_enabled)
                {
                    cache_.put_negative(qname, qt);
                }
                trace::warn("[Resolve] {} all IPs blacklisted", qname);
                co_return std::make_pair(fault::code::blocked, memory::vector<net::ip::address>(mr_));
            }
            result.ips = std::move(filtered);
        }

        // 6：TTL 钳制 + 缓存存储
        if (config_.cache_enabled && succeeded(result.error) && !result.ips.empty())
        {
            // 取所有 answer 记录的最小 TTL
            auto ttl = std::uint32_t{0};
            if (!result.response.answers.empty())
            {
                // 钳制到 [ttl_min, ttl_max]，避免缓存过短或过长
                ttl = result.response.min_ttl();
                ttl = std::clamp(ttl, config_.ttl_min, config_.ttl_max);
            }
            // 仅当 TTL 有效时才写入缓存
            if (ttl > 0)
            {
                cache_.put(qname, qt, result.ips, ttl);
            }
        }
        else if (config_.cache_enabled && failed(result.error))
        {
            // 负缓存
            cache_.put_negative(qname, qt);
        }
        else if (config_.cache_enabled && succeeded(result.error) && result.ips.empty())
        {
            // 上游返回成功但无 IP（如 CNAME 委托），写负缓存避免合并等待者反复查询
            cache_.put_negative(qname, qt);
        }

        if (succeeded(result.error))
        {
            trace::debug("[Resolve] {} -> {} IPs in {}ms via {}",
                         qname, result.ips.size(), result.rtt_ms, result.server_addr);
        }
        else
        {
            trace::warn("[Resolve] {} failed: {}", qname, fault::describe(result.error));
        }

        co_return std::make_pair(result.error, std::move(result.ips));
    }

    auto recursor::resolve(const std::string_view host)
        -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>
    {
        // 并行查询 A 和 AAAA（禁用 IPv6 时跳过 AAAA）
        using namespace boost::asio::experimental::awaitable_operators;
        using result_t = std::pair<fault::code, memory::vector<net::ip::address>>;

        result_t result6{fault::code::success, memory::vector<net::ip::address>(mr_)};
        if (config_.disable_ipv6)
        {
            auto result4 = co_await query_pipeline(host, qtype::a);
            co_return std::move(result4);
        }
        auto [result4, result6_out] = co_await (query_pipeline(host, qtype::a) && query_pipeline(host, qtype::aaaa));
        result6 = std::move(result6_out);

        // 合并结果
        memory::vector<net::ip::address> all_ips(mr_);
        all_ips.reserve(result4.second.size() + result6.second.size());
        all_ips.insert(all_ips.end(), result4.second.begin(), result4.second.end());
        all_ips.insert(all_ips.end(), result6.second.begin(), result6.second.end());

        if (all_ips.empty())
        {
            // 至少有一种查询成功才视为成功（但无 IP）
            if (succeeded(result4.first) || succeeded(result6.first))
            {
                co_return std::make_pair(fault::code::dns_failed, std::move(all_ips));
            }
            co_return std::make_pair(fault::code::dns_failed, std::move(all_ips));
        }

        co_return std::make_pair(fault::code::success, std::move(all_ips));
    }

    auto recursor::resolve_tcp(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>>
    {
        const auto port_num = static_cast<std::uint16_t>(std::stoi(std::string(port)));

        // 并行查询 A 和 AAAA（禁用 IPv6 时跳过 AAAA）
        using namespace boost::asio::experimental::awaitable_operators;
        using ip_result_t = std::pair<fault::code, memory::vector<net::ip::address>>;

        ip_result_t result6{fault::code::success, memory::vector<net::ip::address>(mr_)};
        ip_result_t result4{fault::code::dns_failed, memory::vector<net::ip::address>(mr_)};

        if (config_.disable_ipv6)
        {
            result4 = co_await query_pipeline(host, qtype::a);
        }
        else
        {
            auto [r4, r6] = co_await (query_pipeline(host, qtype::a) && query_pipeline(host, qtype::aaaa));
            result4 = std::move(r4);
            result6 = std::move(r6);
        }

        memory::vector<tcp::endpoint> endpoints(mr_);
        endpoints.reserve(result4.second.size() + result6.second.size());

        for (const auto &ip : result4.second)
        {
            endpoints.emplace_back(ip, port_num);
        }
        for (const auto &ip : result6.second)
        {
            endpoints.emplace_back(ip, port_num);
        }

        if (endpoints.empty())
        {
            co_return std::make_pair(fault::code::dns_failed, std::move(endpoints));
        }

        co_return std::make_pair(fault::code::success, std::move(endpoints));
    }

    auto recursor::resolve_udp(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<fault::code, udp::endpoint>>
    {
        // 先尝试 A 记录，再尝试 AAAA（禁用 IPv6 时跳过）
        auto [ec4, ips4] = co_await query_pipeline(host, qtype::a);

        const auto port_num = static_cast<std::uint16_t>(std::stoi(std::string(port)));

        if (!ips4.empty())
        {
            co_return std::make_pair(fault::code::success, udp::endpoint(ips4.front(), port_num));
        }

        // 禁用 IPv6 时不再回退 AAAA
        if (!config_.disable_ipv6)
        {
            auto [ec6, ips6] = co_await query_pipeline(host, qtype::aaaa);
            if (!ips6.empty())
            {
                co_return std::make_pair(fault::code::success, udp::endpoint(ips6.front(), port_num));
            }
        }

        co_return std::make_pair(fault::code::dns_failed, udp::endpoint{});
    }

} // namespace ngx::resolve
