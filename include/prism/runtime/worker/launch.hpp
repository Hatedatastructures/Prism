/**
 * @file launch.hpp
 * @brief 会话启动与连接分发模块
 * @details 新连接经 acceptor 接收后，通过本模块完成 socket 预配置、
 *          session_resources 构造、会话创建和认证设置等初始化工作。
 *          分发函数支持跨线程将 socket 投递到目标 worker 的事件循环中执行。
 */
#pragma once

#include <prism/resource/worker.hpp>
#include <prism/user/stats/runtime.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

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
     * @brief 预配置 TCP socket 参数（TCP_NODELAY；收发缓冲交系统自动调优）
     */
    auto prime(tcp::socket &socket) noexcept -> void;

    /**
     * @struct launch_params
     * @brief 会话启动参数
     */
    struct launch_params
    {
        std::shared_ptr<psm::resource::worker> worker; ///< worker 资源（共享所有权）
        std::shared_ptr<psm::stats::runtime::worker_load> metrics; ///< 负载监控
        tcp::socket socket;                                        ///< 已连接的 socket
    };

    /**
     * @brief 连接会话启动回调
     * @details 回调在目标 worker 的 io_context 上执行，参数持有 L2 资源共享所有权。
     */
    using ConnectionLauncher = std::function<void(launch_params)>;

    struct dispatch_entry;

    /**
     * @class dispatch_state
     * @brief 已入队连接的无阻塞取消状态
     * @details stop 只取消尚未开始的 entry；已开始的 entry 仍在 worker
     *          executor 上收口，避免 launcher 在调用 stop 的线程执行。
     */
    class dispatch_state final
    {
    public:
        dispatch_state();
        ~dispatch_state();

        dispatch_state(const dispatch_state &) = delete;
        auto operator=(const dispatch_state &) -> dispatch_state & = delete;

        [[nodiscard]] auto add(std::shared_ptr<dispatch_entry> entry) -> bool;
        auto remove(const std::shared_ptr<dispatch_entry> &entry) -> void;
        auto cancel() noexcept -> void;

    private:
        std::atomic<bool> stopped_{false};
        std::atomic<std::shared_ptr<const std::vector<std::shared_ptr<dispatch_entry>>>> pending_;
    };

    /**
     * @brief 启动新会话（worker 线程内调用）
     */
    auto start(launch_params params) -> void;

    /**
     * @brief 将 socket 分发到目标 worker 的事件循环
     */
    auto dispatch(launch_params params, ConnectionLauncher launcher = {},
                  std::shared_ptr<dispatch_state> state = {}) -> void;

} // namespace psm::runtime::worker::launch
