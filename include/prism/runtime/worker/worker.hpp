/**
 * @file worker.hpp
 * @brief Worker 线程核心实现
 * @details worker 类持 shared_ptr<worker_resources>，集中管理 per-worker
 *          资源（ioc/pool/router/dns/routes/outbound/traffic/tracker/tasks）。
 *          从主线程接收分发过来的 socket，创建会话并处理数据转发。
 *          通过负载快照向负载均衡器报告当前负载情况。
 */
#pragma once

#include <prism/account/stats/runtime.hpp>
#include <prism/resource/worker.hpp>
#include <prism/runtime/front/balancer.hpp>

#include <boost/asio.hpp>

#include <memory>


namespace psm::runtime::worker
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @class worker
     * @brief 代理服务工作线程核心类
     * @details worker 持 shared_ptr<worker_resources>，资源所有权由 shared_ptr
 *          引用计数保证。session_resources 也持 shared_ptr<worker_resources>
 *          共享所有权，析构级联安全。
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
         * @param global_ctx 进程级资源（与所有 worker 共享）
         */
        explicit worker(std::shared_ptr<psm::resource::process> global_ctx);

        auto run() -> void;
        auto stop() -> void;
        ~worker();

        auto dispatch_socket(tcp::socket socket) -> void;

        [[nodiscard]] auto load_snapshot() const noexcept
            -> ::psm::stats::worker_snapshot;

        [[nodiscard]] auto tasks() noexcept -> psm::coroutine::task_registry &
        {
            return resources_->tasks;
        }

        [[nodiscard]] auto alive() const noexcept -> bool
        {
            return resources_->alive();
        }

        [[nodiscard]] auto resources() const noexcept
            -> std::shared_ptr<psm::resource::worker>
        {
            return resources_;
        }

    private:
        std::shared_ptr<psm::resource::worker> resources_;
        psm::stats::runtime::worker_load metrics_;
    };

} // namespace psm::runtime::worker
