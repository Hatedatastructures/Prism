/**
 * @file worker.hpp
 * @brief Worker 线程核心实现
 * @details 本文件定义了 worker 类，它是代理服务的工作线程核心组件。
 * 每个 worker 拥有独立的 io_context 事件循环、连接池、路由表和
 * 统计状态。worker 从主线程接收分发过来的 socket，创建会话并
 * 处理数据转发。通过负载快照向负载均衡器报告当前负载情况。
 */
#pragma once

#include <memory>

#include <boost/asio.hpp>

#include <prism/agent/front/balancer.hpp>
#include <prism/resolve/router.hpp>
#include <prism/agent/context.hpp>
#include <prism/config.hpp>
#include <prism/agent/worker/stats.hpp>
#include <prism/agent/worker/tls.hpp>
#include <prism/channel/connection/pool.hpp>
#include <prism/outbound/direct.hpp>

namespace psm::agent::account
{
    class directory;
} // namespace psm::agent::account

namespace psm::agent::worker
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using tcp = boost::asio::ip::tcp;
    using connection_pool = psm::channel::connection_pool;

    /**
     * @class worker
     * @brief 代理服务工作线程核心类
     * @details worker 是代理服务处理连接的核心单元，封装了事件循环、
     * 连接池、路由表、TLS 上下文和统计状态等完整资源。构造时根据
     * 配置初始化所有组件，包括解析反向代理路由规则、设置正向代理
     * 端点、创建 TLS 上下文等。运行时通过 dispatch_socket 接收
     * 主线程分发的连接，在本地事件循环中创建会话并处理数据转发。
     * 内部启动延迟监控协程，持续采集事件循环负载情况。
     * @note worker 对象应在独立线程中创建和运行，run 方法会阻塞
     * 直到事件循环停止
     * @warning worker 不可跨线程共享，所有成员访问必须在 worker
     * 线程内进行，只有 dispatch_socket 和 load_snapshot 方法
     * 是线程安全的
     * @throws std::bad_alloc 如果内存分配失败
     */
    class worker
    {
    public:
        /**
         * @brief 构造 worker 实例
         * @details 根据配置初始化 worker 的所有核心组件。首先创建
         * io_context 作为事件循环引擎，然后初始化连接池和路由表，
         * 接着根据证书配置创建 TLS 上下文，最后组装服务端和 worker
         * 上下文对象。构造过程中会解析配置中的反向代理路由规则，
         * 将主机名映射到后端端点，并设置正向代理的默认目标端点。
         * 无效的路由配置会被记录警告日志并跳过。
         * @param cfg 代理服务配置，包含路由规则和资源限制
         * @param account_store 账户注册表，用于认证功能
         * @throws std::bad_alloc 如果内存分配失败
         */
        explicit worker(const psm::config &cfg, std::shared_ptr<account::directory> account_store);

        /**
         * @brief 启动 worker 事件循环
         * @details 首先在事件循环中启动延迟监控协程，然后阻塞运行
         * io_context 直到被外部停止。该方法应在 worker 专用线程中
         * 调用，会一直阻塞直到事件循环停止。
         */
        void run();

        /**
         * @brief 将 socket 分发到 worker 事件循环
         * @details 该方法是线程安全的，可从主线程或其他 worker 线程
         * 调用。将已连接的 socket 投递到本 worker 的 io_context 中
         * 异步处理，实现跨线程连接分发。实际处理逻辑由
         * launch::dispatch 完成，包括 socket 预配置和会话创建。
         * @param socket 已连接的 TCP socket，将被移动到分发任务中
         */
        void dispatch_socket(tcp::socket socket);

        /**
         * @brief 获取当前负载快照
         * @details 该方法是线程安全的，供负载均衡器查询当前 worker
         * 的负载情况。返回包含活跃会话数、待处理连接数和事件循环
         * 延迟的快照结构体。
         * @return 当前负载快照，用于负载均衡决策
         */
        [[nodiscard]] auto load_snapshot() const noexcept
            -> front::worker_load_snapshot;

    private:
        net::io_context ioc_;                                // 事件循环上下文，单线程运行
        connection_pool pool_;                               // 连接池，管理到后端的连接复用
        resolve::router router_;                             // 路由表，决定请求转发目标
        std::shared_ptr<ssl::context> ssl_ctx_;              // TLS 上下文，为空表示明文模式
        std::unique_ptr<outbound::direct> outbound_direct_;  // 直连出站代理
        stats::state metrics_;                               // 统计状态，记录负载指标
        server_context server_ctx_;                          // 服务端全局上下文，包含配置和共享资源
        worker_context worker_ctx_;                          // worker 线程局部上下文，包含事件循环和内存池
    };
}
