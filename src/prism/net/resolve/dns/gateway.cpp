#include <prism/net/resolve/dns/gateway.hpp>

#include <utility>

namespace psm::resolve::dns
{
    gateway::gateway(gateway_options opts)
        : ioc_(opts.ioc),
          mr_(opts.mr ? opts.mr : memory::current_resource()),
          resolver_(make_resolver(ioc_, std::move(opts.dns_cfg), mr_)),
          cfg_()
    {
    }

    auto gateway::resolve_tcp(
        std::string_view host, std::string_view port,
        std::shared_ptr<trace::trace_context> /*trace*/)
        -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>>
    {
        total_queries_.fetch_add(1, std::memory_order_relaxed);
        if (!resolver_)
        {
            failures_.fetch_add(1, std::memory_order_relaxed);
            co_return std::make_pair(fault::code::dns_failed, memory::vector<tcp::endpoint>{mr_});
        }
        upstream_queries_.fetch_add(1, std::memory_order_relaxed);
        auto result = co_await resolver_->resolve_tcp(host, port);
        if (fault::failed(result.first))
        {
            failures_.fetch_add(1, std::memory_order_relaxed);
        }
        co_return result;
    }

    auto gateway::resolve_udp(
        std::string_view host, std::string_view port,
        std::shared_ptr<trace::trace_context> /*trace*/)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
    {
        total_queries_.fetch_add(1, std::memory_order_relaxed);
        if (!resolver_)
        {
            failures_.fetch_add(1, std::memory_order_relaxed);
            co_return std::make_pair(fault::code::dns_failed, net::ip::udp::endpoint{});
        }
        upstream_queries_.fetch_add(1, std::memory_order_relaxed);
        auto result = co_await resolver_->resolve_udp(host, port);
        if (fault::failed(result.first))
        {
            failures_.fetch_add(1, std::memory_order_relaxed);
        }
        co_return result;
    }

    auto gateway::ipv6_disabled() const noexcept -> bool
    {
        return resolver_ ? resolver_->ipv6_disabled() : false;
    }

    auto gateway::stats() const noexcept -> gateway_stats
    {
        return gateway_stats{
            total_queries_.load(std::memory_order_relaxed),
            cache_hits_.load(std::memory_order_relaxed),
            upstream_queries_.load(std::memory_order_relaxed),
            failures_.load(std::memory_order_relaxed),
            ipv6_filtered_.load(std::memory_order_relaxed)};
    }

} // namespace psm::resolve::dns
