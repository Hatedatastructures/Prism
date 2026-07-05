#include <prism/instance/worker/worker.hpp>

#include <prism/account/directory.hpp>
#include <prism/foundation/coroutine/registry.hpp>
#include <prism/instance/worker/launch.hpp>
#include <prism/trace/trace.hpp>

#include <boost/asio/co_spawn.hpp>

#include <memory>
#include <string_view>
#include <utility>

using namespace psm::trace;

namespace psm::instance::worker
{
    namespace ctx = psm::context;

    // 构造 worker：先创建 SSL 上下文（由 tls::make 加载证书），随后构造
    // worker::resources（资源伞对象，内部初始化所有 per-worker 资源），
    // 再组装服务端/worker 上下文对象（ctx::server / ctx::worker）。
    // ctx::worker 持有的 router& / outbound* / traffic* / tracker* / tasks*
    // 全部指向 resources_ 内部成员，resources_ 必须在 worker_ctx_ 之前析构
    // 由成员声明顺序自然保证。
    worker::worker(const psm::config &cfg, std::shared_ptr<account::directory> account_store)
        : resources_(std::make_shared<psm::worker::resources>(
              psm::worker::options{
                  cfg,
                  account_store,
                  tls::make(cfg.instance),
                  memory::system::local_pool()})),
          ssl_ctx_(resources_->ssl_ctx()),
          server_ctx_{std::atomic<std::shared_ptr<const psm::config>>{}, ssl_ctx_, std::move(account_store)},
          worker_ctx_{resources_->ioc(), resources_->borrow(), memory::system::local_pool()}
    {
        server_ctx_.cfg.store(std::make_shared<const psm::config>(cfg));
    }


    // 启动 worker：先 spawn metrics 观测协程到 resources_->tasks()，
    // 随后调 resources_->run() 进入事件循环阻塞。resources_->run() 内部
    // 启动连接池后台清理 + ioc_.run()，异常时标记 alive_=false 后重抛。
    void worker::run()
    {
        resources_->tasks().spawn_tracked("metrics.observe", metrics_.observe(resources_->ioc()));
        resources_->run();
    }


    // 停止 worker：触发 ioc_.stop() 使阻塞在 run() 的线程退出。
    // 实际的 detached 协程清理在 worker::resources 析构时完成。
    void worker::stop()
    {
        resources_->stop();
    }


    worker::~worker() = default;


    // 接收来自 Listener 的新连接，投递到本 worker 的 io_context。
    // 由 Balancer 调用：当 listener 收到新连接后，balancer 根据负载情况
    // 选出 worker，然后调用本方法把 socket 传过来。launch::dispatch 内部
    // 创建会话对象，开始协议探测和处理。
    void worker::dispatch_socket(tcp::socket socket)
    {
        launch::dispatch(launch::launch_params{server_ctx_, worker_ctx_, metrics_, std::move(socket)});
    }


    // 采集当前 worker 的负载快照，供 Balancer 做调度决策。
    // 聚合 metrics（活跃会话/待分发/事件循环延迟）和 resources_->stats()
    // （协程/连接池/流量/健康度）。
    auto worker::load_snapshot() const noexcept
        -> ::psm::stats::worker_snapshot
    {
        auto snapshot = metrics_.snapshot();
        const auto res_stats = resources_->stats();
        snapshot.active_tasks = res_stats.tasks.active;
        snapshot.spawned_total = res_stats.tasks.total_spawned;
        snapshot.cancelled_total = res_stats.tasks.total_cancelled;
        snapshot.alive = res_stats.alive;
        return snapshot;
    }

} // namespace psm::instance::worker
