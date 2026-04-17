/**
 * @file launch.hpp
 * @brief 会话启动与连接分发模块
 * @details 本文件提供新连接的预处理和会话启动功能。当 acceptor
 * 接收新连接后，通过本模块完成 socket 预配置、会话创建和认证
 * 设置等初始化工作。分发函数支持跨线程将 socket 投递到目标
 * worker 的事件循环中执行，实现负载均衡的连接分发机制。
 */

#pragma once

#include <optional>

#include <boost/asio.hpp>

#include <prism/agent/context.hpp>
#include <prism/agent/worker/stats.hpp>

namespace psm::agent::worker::launch
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @brief 将 socket 的 executor 从当前 io_context 迁移到目标
     * io_context
     * @details socket 被 move 后 executor 不会改变，导致后续异步
     * 操作仍在原线程上执行。该函数通过释放原生句柄并重新绑定到
     * 目标 io_context 来解决这个问题。迁移失败时返回空 optional。
     * @param sock 待迁移的 socket，迁移后变为空壳
     * @param target_ioc 目标 io_context，迁移后 socket 的 executor
     * 将绑定到它
     * @return 迁移后的新 socket，失败时为空
     */
    [[nodiscard]] std::optional<tcp::socket> migrate_executor(tcp::socket &sock, net::io_context &target_ioc) noexcept;

    /**
     * @brief 预配置 TCP socket 参数
     * @details 对新接收的 socket 进行性能优化配置。主要设置三项
     * 参数：打开 TCP_NODELAY 禁用 Nagle 算法以降低小包延迟，
     * 设置接收缓冲区大小以匹配应用层吞吐需求，设置发送缓冲区
     * 大小以优化数据发送效率。所有操作均忽略错误，因为 socket
     * 配置失败不应阻断连接处理。
     * @param socket 待配置的 TCP socket
     * @param buffer_size 接收和发送缓冲区大小，单位字节
     */
    void prime(tcp::socket &socket, std::uint32_t buffer_size) noexcept;

    /**
     * @brief 启动新会话
     * @details 在 worker 线程中创建并启动一个完整的会话对象。
     * 该函数完成以下工作：首先从统计模块获取活跃会话计数器
     * 并设置关闭回调，确保会话结束时正确递减计数；然后创建
     * 可靠传输层封装底层 socket；接着根据配置决定是否启用
     * 认证，设置凭证验证器；最后调用会话的 start 方法开始
     * 处理数据。如果启动过程中发生异常，需要手动调用
     * session_close 确保统计计数正确。
     * @param server 服务端全局上下文，包含配置和账户存储
     * @param worker 当前 worker 的线程局部上下文
     * @param metrics 当前 worker 的统计状态对象
     * @param socket 已连接的 TCP socket，将被移动到会话中
     * @throws 可能抛出会话创建或启动过程中的异常
     */
    void start(server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket);

    /**
     * @brief 将 socket 分发到目标 worker 的事件循环
     * @details 该函数实现了跨线程连接分发机制。主线程 acceptor
     * 接收新连接后调用此函数，将 socket 投递到指定 worker 的
     * io_context 中异步执行。分发过程会先递增待处理计数，投递
     * 成功后立即递减，这样负载均衡器可以感知各 worker 的排队
     * 压力。在 worker 线程中执行时，会先检查 socket 是否仍然
     * 有效，然后调用 prime 进行参数优化，最后调用 start 启动
     * 会话。所有异常都会被捕获并记录日志，不会传播到事件循环
     * 外部。
     * @param ioc 目标 worker 的 io_context
     * @param server 服务端全局上下文
     * @param worker 当前 worker 的线程局部上下文
     * @param metrics 当前 worker 的统计状态对象
     * @param socket 已连接的 TCP socket，将被移动到投递任务中
     */
    void dispatch(net::io_context &ioc, server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket);
} // namespace psm::agent::worker::launch
