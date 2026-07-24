/**
 * @file launch.hpp
 * @brief 会话启动与连接分发模块
 * @details 新连接经 acceptor 接收后，通过本模块完成 socket 预配置、
 *          session_resources 构造、会话创建和认证设置等初始化工作。
 *          分发函数支持跨线程将 socket 投递到目标 worker 的事件循环中执行。
 */
#pragma once

#include <prism/account/stats/runtime.hpp>
#include <prism/resource/worker.hpp>

#include <boost/asio.hpp>

#include <optional>


namespace psm::runtime::worker::launch
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @brief 将 socket 的 executor 从当前 io_context 迁移到目标 io_context
     */
    [[nodiscard]] auto migrate_executor(tcp::socket &sock, net::io_context &target_ioc) noexcept
        -> std::optional<tcp::socket>;

    /**
     * @brief 预配置 TCP socket 参数（TCP_NODELAY + 收发缓冲区）
     */
    auto prime(tcp::socket &socket, std::uint32_t buffer_size) noexcept -> void;

    /**
     * @struct launch_params
     * @brief 会话启动参数
     */
    struct launch_params
    {
        std::shared_ptr<psm::resource::worker> worker; ///< worker 资源（共享所有权）
        psm::stats::runtime::worker_load &metrics;                ///< 负载监控
        tcp::socket socket;                                       ///< 已连接的 socket
    };

    /**
     * @brief 启动新会话（worker 线程内调用）
     */
    auto start(launch_params params) -> void;

    /**
     * @brief 将 socket 分发到目标 worker 的事件循环
     */
    auto dispatch(launch_params params) -> void;

} // namespace psm::runtime::worker::launch
