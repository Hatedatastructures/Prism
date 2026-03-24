#include <forward-engine/agent/worker/worker.hpp>

namespace ngx::agent::worker
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
        // 心跳看门狗：每秒打印一次，如果心跳中断说明 io_context 被阻塞
        net::co_spawn(ioc_,
            []() -> net::awaitable<void>
            {
                try
                {
                    net::steady_timer timer(co_await net::this_coro::executor);
                    while (true)
                    {
                        timer.expires_after(std::chrono::seconds(1));
                        boost::system::error_code ec;
                        co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
                        if (ec)
                            break;
                        // 心跳看门狗：仅保持 io_context 活跃，不输出日志
                    }
                }
                catch (const std::exception &e)
                {
                    trace::error("[Worker] heartbeat exception: {}", e.what());
                }
            },
            net::detached);

        net::co_spawn(ioc_, metrics_.observe(ioc_), net::detached);
        pool_.start();
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
} // namespace ngx::agent::worker
