/**
 * @file registry.hpp
 * @brief detached 协程注册表
 * @details 提供 task_registry 替代 net::detached 模式。worker 持有一个实例，
 * 所有 detached 协程通过 spawn_tracked() 注册，析构前调用
 * cancel_and_wait() 保证优雅退出。配套 task_stats 暴露协程级观测指标，
 * 由 worker_snapshot 聚合上报。
 *
 * 设计要点：
 *   - task_token 通过 shared_ptr 由 registry 和 co_spawn completion 共享持有，
 *     任一方释放后通过析构通知 registry 注销。
 *   - 单线程使用（每 worker 一个实例），tokens_ 操作无需锁。
 *   - cancel_and_wait 通过 io_context::stop() 触发取消，配合外部 ioc.run()
 *     退出后 token 自然 release，避免引入跨线程同步。
 *
 * @note 命名空间 psm::coroutine，与 psm::net（boost::asio）解耦
 * @warning 跨线程调用 spawn_tracked 行为未定义
 */
#pragma once

#include <prism/foundation/memory/container.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>


namespace psm::coroutine
{
    namespace net = boost::asio;

    class task_registry;

    /**
     * @struct task_stats
     * @brief 协程统计快照
     * @details 提供活跃/累计/取消三类计数，由 task_registry::stats() 返回，
     * 上报到 worker_snapshot 供 balancer/HTTP API 查询。
     * @note 所有字段为原子计数器松散一致快照
     */
    struct task_stats
    {
        std::size_t active{0};          ///< 当前活跃 detached 协程数
        std::size_t total_spawned{0};   ///< 历史累计 spawned
        std::size_t total_released{0};  ///< 历史累计正常完成
        std::size_t total_cancelled{0}; ///< 历史累计因 worker 关闭被取消
    };

    /**
     * @class task_token
     * @brief 协程令牌（RAII 注销）
     * @details detached 协程完成时通过 release() 注销自身。生命周期由
     * task_registry 内部持有 + co_spawn completion 捕获共同管理，外部不可
     * 直接持有。registry_ 是裸指针，registry 析构时所有 token 必然先被
     * release（由 cancel_and_wait 保证）。
     * @note 继承 enable_shared_from_this 以便在 completion handler 中保活
     */
    class task_token : public std::enable_shared_from_this<task_token>
    {
    public:
        /**
         * @brief 构造令牌
         * @param owner 关联的注册表引用
         * @param label 协程标签，用于日志诊断
         */
        task_token(task_registry &owner, std::string_view label)
            : owner_(&owner), label_(label, memory::current_resource())
        {
        }

        ~task_token() noexcept;

        task_token(const task_token &) = delete;
        auto operator=(const task_token &) -> task_token & = delete;
        task_token(task_token &&) = delete;
        auto operator=(task_token &&) -> task_token & = delete;

        /**
         * @brief 标记完成并从注册表注销
         * @details 幂等，多次调用安全。registry 在析构前会先 cancel_and_wait，
         * 因此 release 时 owner_ 必然有效。
         */
        auto release() noexcept -> void;

        /**
         * @brief 获取标签
         * @return 协程标签的字符串视图
         */
        [[nodiscard]] auto label() const noexcept -> std::string_view
        {
            return std::string_view(label_);
        }

    private:
        task_registry *owner_;
        memory::string label_;
        bool released_{false};
    };

    /**
     * @class task_registry
     * @brief detached 协程注册表（每 worker 一个）
     * @details 通过 spawn_tracked() 替代 net::detached。worker 析构前调用
     * cancel_and_wait() 保证优雅退出，避免悬挂协程访问已销毁资源。
     * @note 单线程使用（每 worker 一个实例），tokens_ 操作无需锁
     * @warning ioc_ 的生命周期必须长于本对象
     */
    class task_registry
    {
    public:
        friend class task_token;

        /**
         * @brief 构造注册表
         * @param ioc 关联的 io_context，用于 co_spawn
         */
        explicit task_registry(net::io_context &ioc) noexcept
            : ioc_(ioc), tokens_(memory::current_resource())
        {
        }

        ~task_registry() noexcept = default;

        task_registry(const task_registry &) = delete;
        auto operator=(const task_registry &) -> task_registry & = delete;
        task_registry(task_registry &&) = delete;
        auto operator=(task_registry &&) -> task_registry & = delete;

        /**
         * @brief 启动受追踪的协程
         * @tparam Coro 协程类型（返回 net::awaitable<void>）
         * @param label 协程标签（用于日志和调试）
         * @param coro 协程对象
         * @details 创建 task_token 加入 tokens_，co_spawn 到 ioc_，
         * completion handler 持 token shared_ptr 并调用 release()。
         */
        template <typename Coro>
        auto spawn_tracked(std::string_view label, Coro &&coro) -> void;

        /**
         * @brief 取消并清理所有活跃协程令牌
         * @param timeout 参数保留兼容，当前实现不实际等待（见 details）
         * @return true 全部清理完成
         * @details 典型调用场景为 worker 析构链：worker 线程已退出（ioc_.run()
         * 已返回），tokens_ 中残留的是 ioc 析构时未触发 completion handler
         * 的 token。本函数标记 cancelling_ 并直接清理 tokens_，避免后续
         * token 析构访问悬垂 owner_。
         * @note 若在 ioc_ 仍在 run 的线程中调用，本函数无法真实等待协程退出。
         *       真实 graceful shutdown 应在调用前确保 ioc_.stop() 已发出且
         *       worker 线程已 join。
         */
        [[nodiscard]] auto cancel_and_wait(
            std::chrono::milliseconds timeout = std::chrono::seconds(5)) -> bool;

        /**
         * @brief 获取统计快照
         * @return 当前活跃/历史累计/取消计数
         */
        [[nodiscard]] auto stats() const noexcept -> task_stats;

    private:
        /**
         * @brief 内部注销接口（由 task_token::release 调用）
         * @param token 待注销的令牌引用
         * @details 在 tokens_ 中移除该 token 并累加 total_released_ 或
         * total_cancelled_（视 cancel_and_wait 是否在进行）。
         */
        auto release_internal(const task_token &token) noexcept -> void;

        net::io_context &ioc_;
        memory::vector<std::shared_ptr<task_token>> tokens_;
        std::size_t total_spawned_{0};
        std::size_t total_released_{0};
        std::size_t total_cancelled_{0};
        bool cancelling_{false};
    };

    // ── template 实现 ─────────────────────────────────────────────

    template <typename Coro>
    auto task_registry::spawn_tracked(std::string_view label, Coro &&coro) -> void
    {
        auto token = std::make_shared<task_token>(*this, label);
        tokens_.push_back(token);
        ++total_spawned_;

        net::co_spawn(
            ioc_,
            std::forward<Coro>(coro),
            [token](const std::exception_ptr &) noexcept
            {
                token->release();
            });
    }

} // namespace psm::coroutine
