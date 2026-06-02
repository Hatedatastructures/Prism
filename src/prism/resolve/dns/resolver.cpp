#include <prism/resolve/dns/dns.hpp>

#include <prism/resolve/dns/detail/cache.hpp>
#include <prism/resolve/dns/detail/coalescer.hpp>
#include <prism/resolve/dns/detail/rules.hpp>
#include <prism/resolve/dns/detail/utility.hpp>
#include <prism/trace.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <numeric>
#include <optional>

namespace psm::resolve::dns
{

    // ─── concrete implementation of resolver ───────────────────

    class resolver_impl : public resolver
    {
    public:
        explicit resolver_impl(net::io_context &ioc, config cfg, memory::resource_pointer mr = memory::current_resource())
            : ioc_(ioc),
              config_(std::move(cfg)),
              mr_(mr ? mr : memory::current_resource()),
              upstream_(ioc_, mr_), cache_([&]
              {
                  detail::cache_options opts;
                  opts.mr = mr_;
                  opts.ttl = config_.cache_ttl;
                  opts.max_entries = config_.cache_size;
                  if (config_.serve_stale)
                  {
                      opts.stale = detail::stale_policy::serve;
                  }
                  else
                  {
                      opts.stale = detail::stale_policy::discard;
                  }
                  return opts;
              }()),
              rules_(mr_), coalescer_(mr_),
              alive_(std::make_shared<std::atomic<bool>>(true)),
              eviction_timer_(ioc_)
        {
            if (!config_.servers.empty())
            {
                upstream_.set_servers(std::move(config_.servers));
            }
            upstream_.set_mode(config_.mode);
            upstream_.set_timeout(config_.timeout_ms);

            for (const auto &rule : config_.address_rules)
            {
                if (rule.negative)
                {
                    rules_.add_neg_rule(rule.domain);
                }
                else if (!rule.addresses.empty())
                {
                    rules_.add_addr_rule(rule.domain, rule.addresses);
                }
            }
            for (const auto &rule : config_.cname_rules)
            {
                rules_.add_cname(rule.domain, rule.target);
            }

            net::co_spawn(ioc_, eviction_loop(), net::detached);
        }

        ~resolver_impl() override
        {
            if (alive_)
            {
                alive_->store(false);
            }
            eviction_timer_.cancel();
        }

        [[nodiscard]] auto resolve(std::string_view host)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>> override
        {
            using boost::asio::experimental::awaitable_operators::operator&&;

            if (config_.disable_ipv6)
            {
                auto result4 = co_await query_pipeline(host, detail::qtype::a);
                co_return std::move(result4);
            }
            auto query_a = query_pipeline(host, detail::qtype::a);
            auto query_aaaa = query_pipeline(host, detail::qtype::aaaa);
            auto [result4, result6] = co_await (std::move(query_a) && std::move(query_aaaa));

            memory::vector<net::ip::address> all_ips(mr_);
            all_ips.reserve(result4.second.size() + result6.second.size());
            all_ips.insert(all_ips.end(), result4.second.begin(), result4.second.end());
            all_ips.insert(all_ips.end(), result6.second.begin(), result6.second.end());

            if (all_ips.empty())
            {
                co_return std::make_pair(fault::code::dns_failed, std::move(all_ips));
            }

            co_return std::make_pair(fault::code::success, std::move(all_ips));
        }

        [[nodiscard]] auto resolve_tcp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>> override
        {
            const auto port_opt = detail::parse_port(port);
            if (!port_opt)
            {
                co_return std::make_pair(fault::code::invalid_argument, memory::vector<tcp::endpoint>(mr_));
            }
            const auto port_num = *port_opt;

            using boost::asio::experimental::awaitable_operators::operator&&;
            using ip_result_t = std::pair<fault::code, memory::vector<net::ip::address>>;

            ip_result_t result6{fault::code::success, memory::vector<net::ip::address>(mr_)};
            ip_result_t result4{fault::code::dns_failed, memory::vector<net::ip::address>(mr_)};

            if (config_.disable_ipv6)
            {
                result4 = co_await query_pipeline(host, detail::qtype::a);
            }
            else
            {
                auto [r4, r6] = co_await (query_pipeline(host, detail::qtype::a) && query_pipeline(host, detail::qtype::aaaa));
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

        [[nodiscard]] auto ipv6_disabled() const noexcept
            -> bool override
        {
            return config_.disable_ipv6;
        }

        [[nodiscard]] auto resolve_udp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>> override
        {
            auto [ec4, ips4] = co_await query_pipeline(host, detail::qtype::a);

            const auto port_opt = detail::parse_port(port);
            if (!port_opt)
            {
                co_return std::make_pair(fault::code::invalid_argument, net::ip::udp::endpoint{});
            }
            const auto port_num = *port_opt;

            if (!ips4.empty())
            {
                co_return std::make_pair(fault::code::success, net::ip::udp::endpoint(ips4.front(), port_num));
            }

            if (!config_.disable_ipv6)
            {
                auto [ec6, ips6] = co_await query_pipeline(host, detail::qtype::aaaa);
                if (!ips6.empty())
                {
                    co_return std::make_pair(fault::code::success, net::ip::udp::endpoint(ips6.front(), port_num));
                }
            }

            co_return std::make_pair(fault::code::dns_failed, net::ip::udp::endpoint{});
        }

    private:
        [[nodiscard]] auto eviction_loop() -> net::awaitable<void>
        {
            while (alive_->load())
            {
                eviction_timer_.expires_after(std::chrono::seconds(30));
                boost::system::error_code ec;
                co_await eviction_timer_.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (ec == net::error::operation_aborted || !alive_->load())
                    co_return;
                cache_.evict_expired();
            }
        }

        /// @brief IP 过滤：移除黑名单和类型不匹配的 IP，返回过滤后的列表
        [[nodiscard]] auto filter_ips(
            const memory::vector<net::ip::address> &ips,
            const detail::qtype qt) const -> memory::vector<net::ip::address>
        {
            memory::vector<net::ip::address> filtered(mr_);
            filtered.reserve(ips.size());
            const bool want_v4 = (qt == detail::qtype::a);
            const bool want_v6 = (qt == detail::qtype::aaaa);
            for (const auto &ip : ips)
            {
                if (!is_blacklisted(ip) && ip.is_v4() == want_v4 && ip.is_v6() == want_v6)
                {
                    filtered.push_back(ip);
                }
            }
            return filtered;
        }

        /// @brief TTL 钳制 + 缓存存储（成功/失败/空结果三条路径）
        void store_cache(
            const memory::string &qname,
            const detail::qtype qt,
            const query_result &result)
        {
            if (!config_.cache_enabled)
            {
                return;
            }
            if (fault::succeeded(result.error) && !result.ips.empty())
            {
                auto ttl = std::uint32_t{0};
                if (!result.response.answers.empty())
                {
                    ttl = result.response.min_ttl();
                    ttl = std::clamp(ttl, config_.ttl_min, config_.ttl_max);
                }
                if (ttl > 0)
                {
                    cache_.put({qname, qt, result.ips, ttl});
                }
            }
            else if (fault::failed(result.error) ||
                     (fault::succeeded(result.error) && result.ips.empty()))
            {
                cache_.put_negative(qname, qt, config_.negative_ttl);
            }
        }

        [[nodiscard]] auto check_rules(std::string_view qname)
            -> std::optional<std::pair<fault::code, memory::vector<net::ip::address>>>
        {
            if (const auto rule = rules_.match(qname); rule)
            {
                if (rule->blocked)
                {
                    trace::debug("[Resolve] {} blocked by rule", qname);
                    return std::make_pair(fault::code::blocked, memory::vector<net::ip::address>(mr_));
                }
                if (rule->negative)
                {
                    trace::debug("[Resolve] {} negative rule hit", qname);
                    return std::make_pair(fault::code::success, memory::vector<net::ip::address>(mr_));
                }
                if (!rule->addresses.empty())
                {
                    trace::debug("[Resolve] {} -> static address ({} IPs)", qname, rule->addresses.size());
                    return std::make_pair(fault::code::success, memory::vector<net::ip::address>(rule->addresses));
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] auto check_cache(std::string_view qname, detail::qtype qt)
            -> std::optional<std::pair<fault::code, memory::vector<net::ip::address>>>
        {
            if (!config_.cache_enabled)
            {
                return std::nullopt;
            }
            if (auto cached = cache_.get(qname, qt); cached)
            {
                if (cached->empty())
                {
                    trace::debug("[Resolve] {} negative cache hit", qname);
                    return std::make_pair(fault::code::dns_failed, std::move(*cached));
                }
                trace::debug("[Resolve] {} cache hit ({} IPs)", qname, cached->size());
                return std::make_pair(fault::code::success, std::move(*cached));
            }
            return std::nullopt;
        }

        [[nodiscard]] auto query_pipeline(std::string_view domain, detail::qtype qt)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>
        {
            const auto qname = normalize(domain, mr_);

            if (auto ruled = check_rules(qname); ruled)
            {
                co_return std::move(*ruled);
            }

            if (auto cached = check_cache(qname, qt); cached)
            {
                co_return std::move(*cached);
            }

            coalescer_.flush_cleanup();

            const auto qt_str = std::to_string(static_cast<std::uint16_t>(qt));
            const auto key = coalescer_.make_key(qname, qt_str);
            const auto [flight_it, is_new] = coalescer_.find_create(key, ioc_.get_executor());

            if (!is_new)
            {
                if (!flight_it->ready)
                {
                    ++flight_it->waiters;
                    boost::system::error_code ignored;
                    co_await flight_it->timer.async_wait(net::redirect_error(net::use_awaitable, ignored));
                    --flight_it->waiters;
                }

                detail::coalescer::cleanup_flight(flight_it);

                if (auto rechecked = check_cache(qname, qt); rechecked)
                {
                    co_return std::move(*rechecked);
                }

                co_return std::make_pair(fault::code::dns_failed, memory::vector<net::ip::address>(mr_));
            }

            query_result result(mr_);
            try
            {
                result = co_await upstream_.resolve(qname, qt);
            }
            catch (...)
            {
                flight_it->ready = true;
                flight_it->timer.cancel();
                detail::coalescer::cleanup_flight(flight_it);
                throw;
            }

            flight_it->ready = true;
            flight_it->timer.cancel();
            detail::coalescer::cleanup_flight(flight_it);

            if (fault::succeeded(result.error) && !result.ips.empty())
            {
                auto filtered = filter_ips(result.ips, qt);
                if (filtered.empty())
                {
                    if (config_.cache_enabled)
                    {
                        cache_.put_negative(qname, qt, config_.negative_ttl);
                    }
                    trace::warn("[Resolve] {} all IPs blacklisted", qname);
                    co_return std::make_pair(fault::code::blocked, memory::vector<net::ip::address>(mr_));
                }
                result.ips = std::move(filtered);
            }

            store_cache(qname, qt, result);

            if (fault::succeeded(result.error))
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

        [[nodiscard]] static auto normalize(std::string_view domain, memory::resource_pointer mr)
            -> memory::string
        {
            memory::string result(domain, mr);
            auto to_lower = [](std::uint8_t ch)
            {
                return static_cast<char>(std::tolower(ch));
            };
            std::transform(result.begin(), result.end(), result.begin(), to_lower);
            while (!result.empty() && result.back() == '.')
            {
                result.pop_back();
            }
            return result;
        }

        [[nodiscard]] auto is_blacklisted(const net::ip::address &ip) const
            -> bool
        {
            if (ip.is_v4())
            {
                const auto v4 = ip.to_v4();
                const auto addr_uint = v4.to_uint();
                for (const auto &network : config_.blacklist_v4)
                {
                    const auto net_addr = network.address().to_uint();
                    const auto mask = network.netmask().to_uint();
                    if ((addr_uint & mask) == (net_addr & mask))
                    {
                        return true;
                    }
                }
                return false;
            }

            if (ip.is_v6())
            {
                const auto v6 = ip.to_v6();
                const auto &addr_bytes = v6.to_bytes();
                for (const auto &network : config_.blacklist_v6)
                {
                    const auto &net_bytes = network.address().to_bytes();
                    const auto prefix_len = network.prefix_length();
                    bool match = true;
                    for (std::uint32_t i = 0; i < 16 && i * 8 < prefix_len; ++i)
                    {
                        std::uint8_t bits;
                        if (i * 8 + 8 <= prefix_len)
                        {
                            bits = 0xFF;
                        }
                        else
                        {
                            bits = static_cast<std::uint8_t>(0xFF << (8 - (prefix_len - i * 8)));
                        }
                        if ((addr_bytes[i] & bits) != (net_bytes[i] & bits))
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        return true;
                    }
                }
                return false;
            }

            return false;
        }

        net::io_context &ioc_;
        memory::resource_pointer mr_;
        config config_;
        upstream upstream_;
        detail::cache cache_;
        detail::rules_engine rules_;
        detail::coalescer coalescer_;
        std::shared_ptr<std::atomic<bool>> alive_;
        net::steady_timer eviction_timer_;
    };

    // ─── factory ───────────────────────────────────────────────────

    auto make_resolver(net::io_context &ioc, config cfg, memory::resource_pointer mr)
        -> std::unique_ptr<resolver>
    {
        memory::resource_pointer effective_mr;
        if (mr)
        {
            effective_mr = mr;
        }
        else
        {
            effective_mr = memory::current_resource();
        }
        return std::make_unique<resolver_impl>(ioc, std::move(cfg), effective_mr);
    }

} // namespace psm::resolve::dns
