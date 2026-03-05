#include <forward-engine/agent/listener.hpp>

#include <array>

namespace ngx::agent
{
    /**
     * @brief 构造监听器并完成端口绑定
     * @details 仅监听层持有 `acceptor`，避免多 `worker` 抢占同端口。
     */
    listener::listener(const config &cfg, distribute &dispatcher)
        : ioc_(1),acceptor_(ioc_),dispatcher_(dispatcher),
          buffer_size_(cfg.buffer.size),backpressure_delay_(2)
    {
        const tcp::endpoint endpoint(tcp::v4(), cfg.addressable.port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.set_option(net::socket_base::receive_buffer_size(262144));
        acceptor_.set_option(net::socket_base::send_buffer_size(262144));
        acceptor_.bind(endpoint);
        acceptor_.listen();
    }

    /**
     * @brief 启动监听循环
     */
    void listener::listen()
    {
        net::co_spawn(ioc_, accept_loop(), net::detached);
        ioc_.run();
    }

    /**
     * @brief 生成连接亲和键
     * @details
     * - `IPv4`：仅使用源地址 `to_uint()`；
     * - `IPv6`：仅使用源地址高低 64 位折叠。
     */
    auto listener::make_affinity(const tcp::endpoint &endpoint) noexcept 
        -> std::uint64_t
    {
        if (endpoint.address().is_v4())
        {
            return static_cast<std::uint64_t>(endpoint.address().to_v4().to_uint());
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

    /**
     * @brief 接收并投递连接的主循环
     * @details
     * - `accept` 失败时短暂退避；
     * - 依据分流结果可触发背压等待；
     * - 成功后仅做轻量 socket 选项设置并交由目标 `worker`。
     */
    auto listener::accept_loop() -> net::awaitable<void>
    {
        for (;;)
        {
            boost::system::error_code ec;
            tcp::socket socket = co_await acceptor_.async_accept(net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {   // 错误触发短暂退避
                co_await net::steady_timer(ioc_, std::chrono::milliseconds(10)).async_wait(net::use_awaitable);
                continue;
            }

            boost::system::error_code remote_excode;
            const tcp::endpoint remote_endpoint = socket.remote_endpoint(remote_excode);
            const std::uint64_t affinity = remote_excode ? 0ULL : make_affinity(remote_endpoint);
            // 拿到对应的 worker 索引
            const distribute::select_result decision = dispatcher_.select(affinity);
            if (decision.backpressure)
            {
                co_await net::steady_timer(ioc_, backpressure_delay_).async_wait(net::use_awaitable);
            }

            socket.set_option(tcp::no_delay(true));
            socket.set_option(net::socket_base::receive_buffer_size(buffer_size_));
            socket.set_option(net::socket_base::send_buffer_size(buffer_size_));

            dispatcher_.dispatch(decision.worker_index, std::move(socket));
        }
    }
}
