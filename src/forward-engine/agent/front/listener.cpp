#include <forward-engine/agent/front/listener.hpp>

#include <array>

namespace ngx::agent::front
{
    listener::listener(const config &cfg, balancer &dispatcher)
        : ioc_(1),
          acceptor_(ioc_),
          dispatcher_(dispatcher),
          buffer_size_(cfg.buffer.size),
          backpressure_delay_(2)
    {
        const tcp::endpoint endpoint(tcp::v4(), cfg.addressable.port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.set_option(net::socket_base::receive_buffer_size(262144));
        acceptor_.set_option(net::socket_base::send_buffer_size(262144));
        acceptor_.bind(endpoint);
        acceptor_.listen();
    }

    void listener::listen()
    {
        net::co_spawn(ioc_, accept_loop(), net::detached);
        ioc_.run();
    }

    auto listener::make_affinity(const tcp::endpoint &endpoint) noexcept -> std::uint64_t
    {
        if (endpoint.address().is_v4())
        {
            return endpoint.address().to_v4().to_uint();
        }

        const auto bytes = endpoint.address().to_v6().to_bytes();
        std::uint64_t high = 0;
        std::uint64_t low = 0;
        for (std::size_t index = 0; index < 8U; ++index)
        {
            high = (high << 8U) | bytes[index];
            low = (low << 8U) | bytes[index + 8U];
        }
        return high ^ low;
    }

    auto listener::accept_loop() -> net::awaitable<void>
    {
        auto executor = co_await net::this_coro::executor;
        net::steady_timer timer{executor};
        for (;;)
        {
            boost::system::error_code ec;
            tcp::socket socket = co_await acceptor_.async_accept(net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                timer.expires_after(std::chrono::milliseconds(10));
                co_await timer.async_wait(net::use_awaitable);
                continue;
            }

            boost::system::error_code remote_excode;
            const tcp::endpoint remote_endpoint = socket.remote_endpoint(remote_excode);
            const std::uint64_t affinity = remote_excode ? 0ULL : make_affinity(remote_endpoint);
            const balancer::select_result decision = dispatcher_.select(affinity);
            if (decision.backpressure)
            {
                timer.expires_after(backpressure_delay_);
                co_await timer.async_wait(net::use_awaitable);
            }

            socket.set_option(tcp::no_delay(true));
            socket.set_option(net::socket_base::receive_buffer_size(buffer_size_));
            socket.set_option(net::socket_base::send_buffer_size(buffer_size_));

            dispatcher_.dispatch(decision.worker_index, std::move(socket));
        }
    }
} // namespace ngx::agent::front