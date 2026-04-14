#include <prism/agent/worker/worker.hpp>

namespace psm::agent::worker
{
    // 构造 Worker：初始化所有子系统的单例资源。
    // ioc_(1) 表示这个 io_context 只跑在一个线程上（hint=1），
    // 这是实现"每线程一个事件循环"的关键——不需要锁。
    worker::worker(const agent::config &cfg, std::shared_ptr<account::directory> account_store)
        : ioc_(1),
          pool_(ioc_, memory::system::thread_local_pool(), cfg.pool),
          router_(pool_, ioc_, cfg.dns, memory::system::thread_local_pool()),
          ssl_ctx_(tls::make(cfg)),
          server_ctx_{cfg, ssl_ctx_, std::move(account_store)},
          worker_ctx_{ioc_, router_, memory::system::thread_local_pool()}
    {
        // 注册反向代理路由：将虚拟域名映射到实际后端地址。
        // 反向代理模式下，客户端连接代理的 443 端口，代理根据 SNI
        // 将流量透明转发到配置的后端服务。
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

        // 设置正向代理上游（positive）：如果配置了上游代理服务器，
        // 所有出站流量都通过这个上游代理转发（级联代理）。
        if (!server_ctx_.cfg.positive.host.empty() && server_ctx_.cfg.positive.port != 0)
        {
            router_.set_positive_endpoint(
                std::string_view(server_ctx_.cfg.positive.host.data(), server_ctx_.cfg.positive.host.size()),
                server_ctx_.cfg.positive.port);
        }
    }

    // 启动 Worker 事件循环。此方法会阻塞调用线程。
    // 1. 启动连接池（开始池化连接的生命周期管理）
    // 2. 派生一个协程用于定时采集负载指标（活跃会话数、事件循环延迟等）
    // 3. 进入 io_context::run() —— 阻塞在这里，驱动所有异步操作
    void worker::run()
    {
        pool_.start();
        net::co_spawn(ioc_, metrics_.observe(ioc_), net::detached);
        ioc_.run();
    }

    // 接收来自 Listener 的新连接，投递到本 Worker 的 io_context。
    // 由 Balancer 调用——当 Listener 收到新连接后，Balancer 根据
    // 负载情况选出一个 Worker，然后调用这个方法把 socket 传过来。
    // launch::dispatch 内部会创建会话对象，开始协议探测和处理。
    void worker::dispatch_socket(tcp::socket socket)
    {
        launch::dispatch(ioc_, server_ctx_, worker_ctx_, metrics_, std::move(socket));
    }

    // 采集当前 Worker 的负载快照，供 Balancer 做调度决策。
    // 返回的快照包含：活跃会话数、待处理连接数、事件循环延迟。
    // 这些指标是 Balancer 判断是否过载、是否需要全局背压的依据。
    auto worker::load_snapshot() const noexcept
        -> front::worker_load_snapshot
    {
        return metrics_.snapshot();
    }
} // namespace psm::agent::worker
