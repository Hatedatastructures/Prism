#include <prism/agent/worker/worker.hpp>

namespace psm::agent::worker
{
    worker::worker(const agent::config &cfg, std::shared_ptr<account::directory> account_store)
        : ioc_(1),
          pool_(ioc_, memory::system::thread_local_pool(), cfg.pool),
          router_(pool_, ioc_, cfg.dns, memory::system::thread_local_pool()),
          ssl_ctx_(tls::make(cfg)),
          server_ctx_{cfg, ssl_ctx_, std::move(account_store)},
          worker_ctx_{ioc_, router_, memory::system::thread_local_pool()}
    {
        for (const auto &[host, endpoint_config] : server_ctx_.cfg.reverse_map)
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(endpoint_config.host, ec);
            if (!ec && endpoint_config.port != 0)
            {
                router_.add_reverse_route(host, tcp::endpoint(addr, endpoint_config.port));
            }
            else
            {
                trace::warn("Invalid reverse route config for host: {}", host);
            }
        }

        if (!server_ctx_.cfg.positive.host.empty() && server_ctx_.cfg.positive.port != 0)
        {
            router_.set_positive_endpoint(
                std::string_view(server_ctx_.cfg.positive.host.data(), server_ctx_.cfg.positive.host.size()),
                server_ctx_.cfg.positive.port);
        }
    }

    void worker::run()
    {
        pool_.start();
        net::co_spawn(ioc_, metrics_.observe(ioc_), net::detached);
        ioc_.run();
    }

    void worker::dispatch_socket(tcp::socket socket)
    {
        launch::dispatch(ioc_, server_ctx_, worker_ctx_, metrics_, std::move(socket));
    }

    auto worker::load_snapshot() const noexcept
        -> front::worker_load_snapshot
    {
        return metrics_.snapshot();
    }
} // namespace psm::agent::worker
