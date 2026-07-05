#include <prism/worker/resources.hpp>

#include <prism/trace/trace.hpp>

#include <iostream>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include <string_view>
#include <utility>

using namespace psm::trace;

namespace psm::worker
{
    resources::resources(options opts)
        : ioc_(1),
          memory_pool_(opts.mr),
          pool_(ioc_, memory_pool_, opts.cfg.pool),
          router_(std::make_unique<connect::router>(
              connect::router_options{pool_, ioc_, opts.cfg.dns, memory_pool_})),
          dns_gateway_(std::make_unique<resolve::dns::gateway>(
              resolve::dns::gateway_options{ioc_, opts.cfg.dns, memory_pool_})),
          route_table_(memory_pool_),
          ssl_ctx_(std::move(opts.ssl_ctx)),
          outbound_(std::make_unique<outbound::direct>(*router_)),
          traffic_(),
          tracker_(),
          tasks_(ioc_),
          started_at_(std::chrono::steady_clock::now())
    {
        for (const auto &[host, endpoint_config] : opts.cfg.instance.reverse_map)
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(endpoint_config.host, ec);
            if (!ec && endpoint_config.port != 0)
            {
                const auto ep = net::ip::tcp::endpoint(addr, endpoint_config.port);
                router_->add_route(host, ep);
                route_table_.add_route(host, ep);
            }
            else
            {
                trace::warn("Invalid reverse route config for host: {}", host);
            }
        }

        const auto &positive = opts.cfg.instance.positive;
        if (!positive.host.empty() && positive.port != 0)
        {
            const auto positive_host = std::string_view(positive.host.data(), positive.host.size());
            router_->set_endpoint(positive_host, positive.port);
            route_table_.set_forward_endpoint(positive_host, positive.port);
        }

        psm::stats::traffic::traffic_state::register_instance(&traffic_);
    }

    resources::~resources() noexcept
    {
        psm::stats::traffic::traffic_state::unregister_instance(&traffic_);
        if (!tasks_.cancel_and_wait())
        {
            std::cerr << "resources: tasks cancel timed out, residue tokens cleared\n";
        }

        // 析构顺序修复：先 reset dns_gateway_ 和 router_（析构内部 resolver，
        // cancel eviction timer → completion handlers 投递到 ioc_），
        // 然后 poll ioc_ 执行这些 completions（协程 alive_ check → co_return），
        // 最后 stop。这样成员逆序析构时 ioc_ 无 pending operations。
        dns_gateway_.reset();
        router_.reset();

        ioc_.restart();
        ioc_.poll();
        ioc_.stop();
    }

    auto resources::run() -> void
    {
        pool_.start();
        try
        {
            ioc_.run();
        }
        catch (...)
        {
            trace::error("resources event loop crashed, marking unhealthy");
            alive_.store(false, std::memory_order_release);
            throw;
        }
    }

    auto resources::stop() -> void
    {
        ioc_.stop();
    }

    auto resources::borrow() noexcept -> std::weak_ptr<resources>
    {
        return weak_from_this();
    }

    auto resources::stats() const noexcept -> ::psm::worker::stats
    {
        return ::psm::worker::stats{
            tasks_.stats(),
            pool_.stats(),
            traffic_.snapshot(),
            started_at_,
            alive_.load(std::memory_order_acquire)};
    }

} // namespace psm::worker
