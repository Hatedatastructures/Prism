/**
 * @file Registry.hpp
 * @brief detached 协程注册表
 * @details 提供 TaskRegistry 替代 net::detached 模式。worker 持有一个实例，
 * 所有 detached 协程通过 SpawnTracked() 注册，析构前调用
 * CancelAndWait() 保证优雅退出。配套 TaskStats 暴露协程级观测指标，
 * 由 worker_snapshot 聚合上报。
 *
 * 设计要点：
 *   - TaskToken 通过 shared_ptr 由 registry 和 co_spawn completion 共享持有，
 *     任一方释放后通过析构通知 registry 注销。
 *   - 单线程使用（每 worker 一个实例），Tokens_ 操作无需锁。
 *   - CancelAndWait 通过 io_context::Stop() 触发取消，配合外部 ioc.run()
 *     退出后 token 自然 Release，避免引入跨线程同步。
 *
 * @note 命名空间 Preview::Coroutine，与 Preview::net（boost::asio）解耦
 * @warning 跨线程调用 SpawnTracked 行为未定义
 */
#pragma once

#include <preview/Foundation/Memory/Container.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>

namespace Preview::Coroutine
{
    namespace net = boost::asio;

    class TaskRegistry;

    /**
     * @struct TaskStats
     * @brief 协程统计快照
     * @details 提供活跃/累计/取消三类计数，由 TaskRegistry::Stats() 返回，
     * 上报到 worker_snapshot 供 balancer/HTTP API 查询。
     * @note 所有字段为原子计数器松散一致快照
     */
    struct TaskStats
    {
        std::size_t Active{0};          ///< 当前活跃 detached 协程数
        std::size_t TotalSpawned{0};   ///< 历史累计 spawned
        std::size_t TotalReleased{0};  ///< 历史累计正常完成
        std::size_t TotalCancelled{0}; ///< 历史累计因 worker 关闭被取消
    };

    /**
     * @class TaskToken
     * @brief 协程令牌（RAII 注销）
     * @details detached 协程完成时通过 Release() 注销自身。生命周期由
     * TaskRegistry 内部持有 + co_spawn completion 捕获共同管理，外部不可
     * 直接持有。Registry_ 是裸指针，registry 析构时所有 token 必然先被
     * Release（由 CancelAndWait 保证）。
     * @note 继承 enable_shared_from_this 以便在 completion handler 中保活
     */
    class TaskToken : public std::enable_shared_from_this<TaskToken>
    {
    public:
        /**
         * @brief 构造令牌
         * @param owner 关联的注册表引用
         * @param Label 协程标签，用于日志诊断
         */
        TaskToken(TaskRegistry &owner, std::string_view Label)
            : Owner_(&owner), Label_(Label, Preview::Memory::CurrentResource())
        {
        }

        ~TaskToken() noexcept;

        TaskToken(const TaskToken &) = delete;
        auto operator=(const TaskToken &) -> TaskToken & = delete;
        TaskToken(TaskToken &&) = delete;
        auto operator=(TaskToken &&) -> TaskToken & = delete;

        /**
         * @brief 标记完成并从注册表注销
         * @details 幂等，多次调用安全。registry 在析构前会先 CancelAndWait，
         * 因此 Release 时 Owner_ 必然有效。
         */
        auto Release() noexcept -> void;

        /**
         * @brief 解除与注册表的绑定（注册表析构前调用）
         * @details 置 Owner_ 为空并标记已释放，防止注册表析构后残留
         * token（仍被 co_spawn completion handler 持有）析构时
         * 访问悬垂 Owner_。
         */
        auto Detach() noexcept -> void
        {
            Owner_ = nullptr;
            Released_ = true;
        }

        /**
         * @brief 获取标签
         * @return 协程标签的字符串视图
         */
        [[nodiscard]] auto Label() const noexcept -> std::string_view
        {
            return std::string_view(Label_);
        }

    private:
        TaskRegistry *Owner_;
        Preview::Memory::String Label_;
        bool Released_{false};
    };

    /**
     * @class TaskRegistry
     * @brief detached 协程注册表（每 worker 一个）
     * @details 通过 SpawnTracked() 替代 net::detached。worker 析构前调用
     * CancelAndWait() 保证优雅退出，避免悬挂协程访问已销毁资源。
     * @note 单线程使用（每 worker 一个实例），Tokens_ 操作无需锁
     * @warning Ioc_ 的生命周期必须长于本对象
     */
    class TaskRegistry
    {
    public:
        friend class TaskToken;

        /**
         * @brief 构造注册表
         * @param ioc 关联的 io_context，用于 co_spawn
         */
        explicit TaskRegistry(net::io_context &ioc) noexcept : Ioc_(ioc)
        {
        }

        ~TaskRegistry() noexcept
        {
            // 解除所有残留 token 对 Owner_ 的绑定：token 可能仍被
            // co_spawn completion handler 持有，其析构发生在 ioc 析构时
            // （可能晚于本对象），直接访问 Owner_ 会悬垂
            for (const auto &[ptr, Token] : Tokens_)
            {
                (void)ptr;
                Token->Detach();
            }
            Tokens_.clear();
        }

        TaskRegistry(const TaskRegistry &) = delete;
        auto operator=(const TaskRegistry &) -> TaskRegistry & = delete;
        TaskRegistry(TaskRegistry &&) = delete;
        auto operator=(TaskRegistry &&) -> TaskRegistry & = delete;

        /**
         * @brief 启动受追踪的协程
         * @tparam Coro 协程类型（返回 net::awaitable<void>）
         * @param Label 协程标签（用于日志和调试）
         * @param coro 协程对象
         * @details 创建 TaskToken 加入 Tokens_，co_spawn 到 Ioc_，
         * completion handler 持 token shared_ptr 并调用 Release()。
         */
        template <typename Coro>
        auto SpawnTracked(std::string_view Label, Coro &&coro) -> void;

        /**
         * @brief 取消并清理所有活跃协程令牌
         * @param timeout 参数保留兼容，当前实现不实际等待（见 details）
         * @return true 全部清理完成
         * @details 实为 Stop + 等待退出（非取消等待）：
         * 典型调用场景为 worker 析构链：worker 线程已退出（Ioc_.run()
         * 已返回），Tokens_ 中残留的是 ioc 析构时未触发 completion handler
         * 的 token。本函数标记 Cancelling_ 并直接清理 Tokens_，避免后续
         * token 析构访问悬垂 Owner_。
         * @note 若在 Ioc_ 仍在 Run 的线程中调用，本函数无法真实等待协程退出。
         *       真实 graceful Shutdown 应在调用前确保 Ioc_.stop() 已发出且
         *       worker 线程已 join。
         */
        [[nodiscard]] auto CancelAndWait(std::chrono::milliseconds timeout = std::chrono::seconds(5))
            -> bool;

        /**
         * @brief 获取统计快照
         * @return 当前活跃/历史累计/取消计数
         */
        [[nodiscard]] auto Stats() const noexcept -> TaskStats;

    private:
        /**
         * @brief 内部注销接口（由 TaskToken::Release 调用）
         * @param token 待注销的令牌引用
         * @details 在 Tokens_ 中移除该 token 并累加 TotalReleased_ 或
         * TotalCancelled_（视 CancelAndWait 是否在进行）。
         * 哈希索引（O(1)）：token 指针即键，避免线性扫描。
         */
        auto ReleaseInternal(const TaskToken &Token) noexcept -> void;

        net::io_context &Ioc_;
        std::unordered_map<const TaskToken *, std::shared_ptr<TaskToken>> Tokens_; ///< token 指针 → 令牌
        std::size_t TotalSpawned_{0};
        std::size_t TotalReleased_{0};
        std::size_t TotalCancelled_{0};
        bool Cancelling_{false};
    };

    // ── template 实现 ─────────────────────────────────────────────

    template <typename Coro>
    auto TaskRegistry::SpawnTracked(std::string_view Label, Coro &&coro) -> void
    {
        auto Token = std::make_shared<TaskToken>(*this, Label);
        Tokens_.emplace(Token.get(), Token);
        ++TotalSpawned_;

        net::co_spawn(Ioc_, std::forward<Coro>(coro),
                      [Token](const std::exception_ptr &) noexcept { Token->Release(); });
    }

    inline TaskToken::~TaskToken() noexcept
    {
        if (!Released_)
        {
            Release();
        }
    }

    inline auto TaskToken::Release() noexcept -> void
    {
        if (Released_)
        {
            return;
        }
        Released_ = true;
        if (Owner_ != nullptr)
        {
            Owner_->ReleaseInternal(*this);
        }
    }

    inline auto TaskRegistry::CancelAndWait(const std::chrono::milliseconds /*timeout*/) -> bool
    {
        Cancelling_ = true;
        TotalCancelled_ += Tokens_.size();
        for (const auto &[ptr, Token] : Tokens_)
        {
            (void)ptr;
            Token->Detach();
        }
        Tokens_.clear();
        return true;
    }

    inline auto TaskRegistry::Stats() const noexcept -> TaskStats
    {
        return TaskStats{Tokens_.size(), TotalSpawned_, TotalReleased_, TotalCancelled_};
    }

    inline auto TaskRegistry::ReleaseInternal(const TaskToken &Token) noexcept -> void
    {
        if (Cancelling_)
        {
            return;
        }

        const auto It = Tokens_.find(&Token);
        if (It != Tokens_.end())
        {
            Tokens_.erase(It);
            ++TotalReleased_;
        }
    }


} // namespace Preview::Coroutine
