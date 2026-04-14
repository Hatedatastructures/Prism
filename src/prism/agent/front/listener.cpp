#include <prism/agent/front/listener.hpp>

#include <array>

namespace psm::agent::front
{
    // 构造 Listener：解析监听地址，打开 acceptor 并绑定端口。
    // ioc_(1) 表示独立线程的事件循环，不和其他 Worker 共享。
    // backpressure_delay_ 默认 2ms，全局背压时用这个延迟暂停接受。
    listener::listener(const config &cfg, balancer &dispatcher)
        : ioc_(1),acceptor_(ioc_),dispatcher_(dispatcher),
          buffer_size_(cfg.buffer.size),backpressure_delay_(2)
    {
        net::ip::address addr;
        boost::system::error_code ec;
        addr = net::ip::make_address(cfg.addressable.host, ec);
        if (ec)
        {   // 目前不支持 IPv6 地址，仅支持 IPv4 地址
            if (cfg.addressable.host == "localhost")
            {   // 如果为 localhost，则使用回环地址 127.0.0.1
                addr = net::ip::address_v4::loopback();
            }
            else if (cfg.addressable.host == "0.0.0.0" || cfg.addressable.host.empty())
            {   // 如果为 0.0.0.0 或空字符串，则使用所有接口
                addr = net::ip::address_v4::any();
            }
            else
            {
                throw std::system_error(ec, "Invalid listen address: " + std::string(cfg.addressable.host) +
                    ". Use IP address (e.g., 0.0.0.0, 127.0.0.1, ::) instead of hostname.");
            }
        }

        // 设置 socket 选项：
        // - reuse_address：允许端口复用（重启时不用等 TIME_WAIT 过期）
        // - 收发缓冲区大小：从配置中读取，影响吞吐量
        const tcp::endpoint endpoint(addr, cfg.addressable.port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.set_option(net::socket_base::receive_buffer_size(cfg.buffer.size));
        acceptor_.set_option(net::socket_base::send_buffer_size(cfg.buffer.size));
        acceptor_.bind(endpoint);
        acceptor_.listen();
    }

    // 启动监听：派生 accept 循环协程，然后阻塞在 io_context::run()。
    // 和 Worker 一样，Listener 的事件循环也是阻塞式的。
    void listener::listen()
    {
        net::co_spawn(ioc_, accept_loop(), net::detached);
        ioc_.run();
    }

    // 从客户端 IP 地址计算亲和性值，用于 Balancer 的会话亲和性调度。
    // 同一个客户端 IP 总是得到相同的亲和性值，这样 Balancer 会倾向于
    // 把同一客户端的连接分发到同一个 Worker（亲和性首选）。
    //
    // IPv4：直接用 32 位地址（如 192.168.1.1 → 0xC0A80101）。
    // IPv6：16 字节地址折叠为 8 字节（高 8 字节 XOR 低 8 字节）。
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

    // 接受连接的主循环。每轮迭代：
    // 1. 异步等待新连接（accept）
    // 2. accept 失败 → 等待 10ms 后重试（防止错误时 CPU 空转）
    // 3. 计算客户端 IP 的亲和性值
    // 4. 让 Balancer 选一个 Worker（可能触发全局背压）
    // 5. 设置 socket 选项（TCP_NODELAY 禁用 Nagle 算法，减少延迟）
    // 6. 把 socket 交给选中的 Worker
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

            // 获取客户端地址用于亲和性计算
            boost::system::error_code remote_excode;
            const tcp::endpoint remote_endpoint = socket.remote_endpoint(remote_excode);
            const std::uint64_t affinity = remote_excode ? 0ULL : make_affinity(remote_endpoint);

            // 让 Balancer 选择目标 Worker
            const balancer::select_result decision = dispatcher_.select(affinity);

            // 全局背压：所有 Worker 都过载了，暂停接受新连接一小段时间
            if (decision.backpressure)
            {
                timer.expires_after(backpressure_delay_);
                co_await timer.async_wait(net::use_awaitable);
            }

            // TCP_NODELAY 禁用 Nagle 算法——代理场景下延迟敏感，不能等缓冲区填满再发
            socket.set_option(tcp::no_delay(true));
            socket.set_option(net::socket_base::receive_buffer_size(buffer_size_));
            socket.set_option(net::socket_base::send_buffer_size(buffer_size_));

            // 将 socket 移交给选中的 Worker
            dispatcher_.dispatch(decision.worker_index, std::move(socket));
        }
    }
} // namespace psm::agent::front
