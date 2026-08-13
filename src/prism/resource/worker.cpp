#include <prism/diagnose/diagnose.hpp>
#include <prism/resource/worker.hpp>

#include <iostream>
#include <utility>

using namespace psm::diagnose;

namespace psm::resource
{

    worker::worker(options opts)
        : process(std::move(opts.process)), memory(opts.mr), ioc(1),
          dialer_(
              std::make_unique<psm::connect::dialer>(psm::connect::dialer_options{ioc, process->cfg->dns})),
          routes(memory), outbound(std::make_unique<psm::outbound::direct>(*dialer_)), traffic(), rate(),
          tasks(ioc)
    {
        const auto &cfg_ref = *process->cfg;
        for (const auto &[host, ep_cfg] : cfg_ref.instance.reverse_map)
        {
            boost::system::error_code ec;
            const auto addr = boost::asio::ip::make_address(ep_cfg.host, ec);
            if (!ec && ep_cfg.port != 0)
            {
                const auto ep = boost::asio::ip::tcp::endpoint(addr, ep_cfg.port);
                dialer_->add_route(host, ep);
                routes.add_route(host, ep);
            }
            else
            {
                diagnose::warn("Invalid reverse route config for host: {}", host);
            }
        }

        const auto &positive = cfg_ref.instance.positive;
        if (!positive.host.empty() && positive.port != 0)
        {
            const auto positive_host = std::string_view(positive.host.data(), positive.host.size());
            dialer_->set_endpoint(positive_host, positive.port);
            routes.set_forward_endpoint(positive_host, positive.port);
        }

        psm::stats::traffic::traffic_state::register_instance(&traffic);
    }

    worker::~worker() noexcept
    {
        psm::stats::traffic::traffic_state::unregister_instance(&traffic);
        if (!tasks.cancel_and_wait())
        {
            std::cerr << "worker: tasks cancel timed out\n";
        }

        dialer_.reset();

        ioc.restart();
        ioc.poll();
        ioc.stop();
    }

    auto worker::alive() const noexcept -> bool
    {
        return alive_.load(std::memory_order_acquire);
    }

    auto worker::stop() -> void
    {
        ioc.stop();
    }

} // namespace psm::resource
