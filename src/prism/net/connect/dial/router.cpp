#include <prism/net/connect/dial/router.hpp>

#include <prism/net/resolve/dns/detail/utility.hpp>
#include <prism/trace/trace.hpp>

namespace psm::connect
{

    router::router(router_options opts)
        : pool_(opts.pool),
          mr_(memory::effective_mr(opts.mr)),
          dns_(resolve::dns::make_resolver(opts.ioc, std::move(opts.dns_cfg), mr_)),
          reverse_map_(mr_),
          executor_(opts.ioc.get_executor())
    {
    }


    void router::set_endpoint(const std::string_view host, const std::uint16_t port)
    {
        if (host.empty() || port == 0)
        {
            positive_host_.reset();
            positive_port_ = 0;
            return;
        }

        memory::string host_value(mr_);
        host_value.assign(host);
        positive_host_ = std::move(host_value);
        positive_port_ = port;
    }


    void router::add_route(const std::string_view host, const tcp::endpoint &ep)
    {
        memory::string host_key(mr_);
        host_key.assign(host);
        reverse_map_.insert_or_assign(std::move(host_key), ep);
    }


    auto router::async_reverse(const std::string_view host) const
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        const auto route = reverse_map_.find(host);
        if (route == reverse_map_.end())
        {
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        auto [code, conn] = co_await pool_.async_acquire(route->second);
        if (!conn.valid())
        {
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        co_return std::make_pair(fault::code::success, std::move(conn));
    }

} // namespace psm::connect
