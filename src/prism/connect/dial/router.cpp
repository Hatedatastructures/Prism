#include <prism/connect/dial/router.hpp>
#include <prism/resolve/dns/detail/utility.hpp>
#include <prism/trace.hpp>

namespace psm::connect
{
    router::router(connection_pool &pool, net::io_context &ioc, resolve::dns::config dns_cfg,
                   const memory::resource_pointer mr)
        : pool_(pool),
          mr_(mr ? mr : memory::current_resource()),
          dns_(resolve::dns::make_resolver(ioc, std::move(dns_cfg), mr_)),
          reverse_map_(mr_),
          executor_(ioc.get_executor())
    {
    }

    void router::set_positive_endpoint(const std::string_view host, const std::uint16_t port)
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

    void router::add_reverse_route(const std::string_view host, const tcp::endpoint &ep)
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
