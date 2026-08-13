/**
 * @file worker.hpp
 * @brief Worker 线程核心实现
 * @details worker 类持 shared_ptr<worker_resources>，集中管理 per-worker
 *          资源（ioc/pool/router/dns/routes/outbound/traffic/tracker/tasks）。
 *          从主线程接收分发过来的 socket，创建会话并处理数据转发。
 *          通过负载快照向负载均衡器报告当前负载情况。
 */
#pragma once

#include <prism/resource/worker.hpp>
#include <prism/runtime/front/balancer.hpp>
#include <prism/user/stats/runtime.hpp>

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

        /**
         * @brief 运行 worker 事件循环（线程入口）
         */
        auto run() -> void;
        /**
         * @brief 停止 worker 事件循环
         */
        auto stop() -> void;
        /**
         * @brief 析构 worker
         */
        ~worker();

        /**
         * @brief 从主线程接收分发的套接字
         * @param socket 待处理的连接套接字
         */
        auto dispatch_socket(tcp::socket socket) -> void;

        /**
         * @brief 获取当前负载快照
         * @return 包含活跃会话数、待分发数、事件循环延迟的快照
         */
        [[nodiscard]] auto load_snapshot() const noexcept -> ::psm::stats::worker_snapshot;

        /**
         * @brief 获取协程任务注册表
         * @return 任务注册表引用
         */
        [[nodiscard]] auto tasks() noexcept -> psm::coroutine::task_registry &
        {
            return resources_->tasks;
        }

        /**
         * @brief 检查 worker 是否存活
         * @return 始终返回 true
         */
        [[nodiscard]] auto alive() const noexcept -> bool
        {
            return true;
        }

        /**
         * @brief 获取 worker 资源
         * @return worker 资源共享指针
         */
        [[nodiscard]] auto resources() const noexcept -> std::shared_ptr<psm::resource::worker>
        {
            return resources_;
        }

    private:
        std::shared_ptr<psm::resource::worker> resources_; ///< worker 资源（L2）
        psm::stats::runtime::worker_load metrics_;         ///< worker 负载统计
    };

} // namespace psm::runtime::worker
