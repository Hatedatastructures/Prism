/**
 * @file worker.hpp
 * @brief Worker 线程核心实现
 * @details 本文件定义了 worker 类，它是代理服务的工作线程核心组件。
 * worker 持有 worker::resources（io_context / 连接池 / 路由表 / 出站代理 /
 * 流量统计 / 探测追踪 / 协程注册表），通过 worker::resources 集中管理生命周期。
 * worker 从主线程接收分发过来的 socket，创建会话并处理数据转发。通过
 * 负载快照向负载均衡器报告当前负载情况。
 */
#pragma once

#include <prism/account/stats/runtime.hpp>
#include <prism/config/config.hpp>
#include <prism/context/context.hpp>
#include <prism/worker/resources.hpp>
#include <prism/instance/front/balancer.hpp>
#include <prism/instance/worker/tls.hpp>

#include <boost/asio.hpp>

#include <memory>


namespace psm::account
{

    class directory;
} // namespace psm::account

namespace psm::instance::worker
{

    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using tcp = boost::asio::ip::tcp;
    namespace ctx = psm::context;

    /**
     * @class worker
     * @brief 代理服务工作线程核心类
     * @details worker 持有 worker::resources（资源伞对象）和 metrics（负载监控），
     * 通过 resources_ 集中管理 io_context / 连接池 / 路由表 / TLS / 出站代理 /
     * 流量统计 / 探测追踪 / 协程注册表。run() 启动事件循环并 spawn metrics
     * 观测协程。dispatch_socket 接收主线程分发的连接，投递到本地事件循环。
     * @note worker 对象应在独立线程中创建和运行，run 方法会阻塞直到事件循环停止
     * @warning worker 不可跨线程共享，所有成员访问必须在 worker 线程内进行，
     *          只有 dispatch_socket 和 load_snapshot 方法是线程安全的
     * @throws std::bad_alloc 如果内存分配失败
     */
    class worker
    {
    public:
        worker(const worker &) = delete;
        auto operator=(const worker &) -> worker & = delete;
        worker(worker &&) = delete;
        auto operator=(worker &&) -> worker & = delete;

        /**
         * @brief 构造 worker 实例
         * @details 创建 SSL 上下文（由 tls::make 完成证书加载），随后构造
         * worker::resources（内部初始化连接池、路由表、出站代理、流量统计、
         * 探测追踪、协程注册表），并组装服务端/worker 上下文对象。
         * worker::resources 的构造会解析反向代理路由表、设置正向代理端点、
         * 注册流量统计实例。无效配置会被记录警告日志并跳过。
         * @param cfg 代理服务配置，包含路由规则和资源限制
         * @param account_store 账户注册表，用于认证功能
         * @throws std::bad_alloc 如果内存分配失败
         */
        explicit worker(const psm::config &cfg, std::shared_ptr<account::directory> account_store);

        /**
         * @brief 启动 worker 事件循环
         * @details 先 spawn metrics 观测协程（通过 resources_->tasks()），
         * 然后调 resources_->run() 阻塞直到事件循环停止。resources_->run()
         * 内部启动连接池后台清理和 ioc_.run()，异常时标记 alive_=false 后重抛。
         */
        void run();

        /**
         * @brief 停止 worker 事件循环
         * @details 调 resources_->stop()，触发 ioc_.stop() 使阻塞在 run()
         * 的线程退出。detached 协程清理在 worker::resources 析构时由
         * cancel_and_wait 完成。
         */
        void stop();

        /**
         * @brief 析构 worker 实例
         * @details resources_ 自动析构（shared_ptr 引用归零），
         * 析构链中 tasks_.cancel_and_wait 清理 detached 协程。
         */
        ~worker();

        /**
         * @brief 将 socket 分发到 worker 事件循环
         * @details 线程安全，可从主线程或其他 worker 线程调用。将已连接的
         * socket 投递到本 worker 的 io_context 中异步处理。实际处理逻辑
         * 由 launch::dispatch 完成，包括 socket 预配置和会话创建。
         * @param socket 已连接的 TCP socket，将被移动到分发任务中
         */
        void dispatch_socket(tcp::socket socket);

        /**
         * @brief 获取当前负载快照
         * @details 线程安全，供负载均衡器查询。聚合 metrics（活跃会话/待分发/
         * 延迟）和 resources_->stats()（协程/连接池/流量/健康度）。
         * @return 当前负载快照，用于负载均衡决策
         */
        [[nodiscard]] auto load_snapshot() const noexcept
            -> ::psm::stats::worker_snapshot;

        /**
         * @brief 获取协程注册表
         * @return resources_->tasks() 引用
         * @details 供 anytls/craft/mux 等模块调用 spawn_tracked 替代
         * net::detached，保证 worker 析构前所有 detached 协程退出。
         */
        [[nodiscard]] auto tasks() noexcept -> coroutine::task_registry &
        {
            return resources_->tasks();
        }

        /**
         * @brief 检查 worker 是否健康
         * @return resources_->alive()，true 健康；false 已崩溃或正在关闭
         * @details 由 worker::resources::run 的异常处理置 false，
         * balancer::select 跳过返 false 的 worker。
         */
        [[nodiscard]] auto alive() const noexcept -> bool
        {
            return resources_->alive();
        }

    private:
        // 声明顺序决定析构顺序：resources_ 必须在 server_ctx_/worker_ctx_ 之前析构，
        // 否则 ctx::worker 持有的 router& 等引用悬垂。
        std::shared_ptr<psm::worker::resources> resources_;
        std::shared_ptr<ssl::context> ssl_ctx_;     // 与 resources_ 共享所有权
        stats::runtime::worker_load metrics_;
        ctx::server server_ctx_;
        ctx::worker_ref worker_ctx_;
    };
}
