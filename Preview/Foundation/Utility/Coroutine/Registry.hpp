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
 *   - 每个 token 拥有独立 cancellation slot，Cancel() 通过 Asio 取消挂起的
 *     异步操作；CancelAndWait() 在同一 executor 上等待 token 真正释放。
 *
 * @note 命名空间 Preview::Coroutine，与 Preview::net（boost::asio）解耦
 * @warning 跨线程调用 SpawnTracked 行为未定义
 */
#pragma once

#include <Preview/Foundation/Memory/Container.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Coroutine
{
    namespace Net = boost::asio;

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
     * 直接持有。Owner_ 是裸指针，registry 析构时会先发出取消并解除绑定。
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
        TaskToken(TaskRegistry &Owner, std::string_view Label)
            : Owner_(&Owner), Label_(Label, Preview::Memory::CurrentResource())
        {
        }

        ~TaskToken() noexcept;

        TaskToken(const TaskToken &) = delete;
        auto operator=(const TaskToken &) -> TaskToken & = delete;
        TaskToken(TaskToken &&) = delete;
        auto operator=(TaskToken &&) -> TaskToken & = delete;

        /**
         * @brief 标记完成并从注册表注销
         * @details 幂等，多次调用安全。registry 正常关闭时应先
         * co_await CancelAndWait()；析构路径则由 Detach() 保证 Owner_ 安全。
        */
        auto Release() noexcept -> void;

        /**
         * @brief 请求取消该协程
         * @details 通过 token 独立的 cancellation slot 传播 terminal cancellation，
         *          重复调用不会重复发信号。
         */
        auto RequestCancel() noexcept -> void;

        /**
         * @brief 查询是否已请求取消
         * @return 已请求取消返回 true
         */
        [[nodiscard]] auto CancelRequested() const noexcept -> bool
        {
            return CancelRequested_;
        }

        /**
         * @brief 获取该 token 的 cancellation slot
         * @return 用于绑定 co_spawn completion token 的 slot
         */
        [[nodiscard]] auto CancellationSlot() noexcept -> Net::cancellation_slot
        {
            return Cancellation_.slot();
        }

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
        friend class TaskRegistry;

        TaskRegistry *Owner_;
        Preview::Memory::String Label_;
        Net::cancellation_signal Cancellation_;
        bool Released_{false};
        bool CancelRequested_{false};
    };

    /**
     * @class TaskRegistry
     * @brief detached 协程注册表（每 worker 一个）
     * @details 通过 SpawnTracked() 替代 net::detached。worker 关闭流程应在
     * 析构前 co_await CancelAndWait()，避免悬挂协程访问已销毁资源。
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
        explicit TaskRegistry(Net::io_context &Ioc) noexcept : Ioc_(Ioc), DrainTimer_(Ioc)
        {
        }

        ~TaskRegistry() noexcept
        {
            // 析构函数不能 co_await，只发出取消并解除 Owner_ 绑定；调用方
            // 若需要确认协程已收口，应在析构前 co_await CancelAndWait()。
            Cancel();
            for (const auto &[Pointer, Token] : Tokens_)
            {
                (void)Pointer;
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
         * @tparam Coro 协程类型（返回 Net::awaitable<void>）
         * @param Label 协程标签（用于日志和调试）
         * @param coro 协程对象
         * @details 创建 TaskToken 加入 Tokens_，co_spawn 到 Ioc_，
         * completion handler 持 token shared_ptr 并调用 Release()。
         */
        template <typename Coro>
        auto SpawnTracked(std::string_view Label, Coro &&CoroObject) -> void;

        /**
         * @brief 请求取消所有活跃协程
         * @details 只发出取消请求，不等待协程完成；可在无法 co_await 的
         *          析构路径调用。重复调用幂等。
         */
        auto Cancel() noexcept -> void;

        /**
         * @brief 取消并等待所有活跃协程收口
         * @param timeout 最长等待时间
         * @return 在超时前所有 token 均释放返回 true，否则返回 false
         * @details 必须在关联 io_context 的 executor 上 co_await。等待期间
         *          不阻塞线程，底层异步操作通过 cancellation slot 收到取消。
         */
        [[nodiscard]] auto CancelAndWait(std::chrono::milliseconds Timeout = std::chrono::seconds(5))
            -> Net::awaitable<bool>;

        /**
         * @brief 获取统计快照
         * @return 当前活跃/历史累计/取消计数
         */
        [[nodiscard]] auto Stats() const noexcept -> TaskStats;

    private:
        /**
         * @brief 内部注销接口（由 TaskToken::Release 调用）
         * @param token 待注销的令牌引用
         * @details 在 Tokens_ 中移除该 token 并按是否请求取消累加
         * TotalReleased_ 或 TotalCancelled_。
         * 哈希索引（O(1)）：token 指针即键，避免线性扫描。
         */
        auto ReleaseInternal(const TaskToken &Token) noexcept -> void;

        Net::io_context &Ioc_;
        Net::steady_timer DrainTimer_;
        std::unordered_map<const TaskToken *, std::shared_ptr<TaskToken>> Tokens_; ///< token 指针 → 令牌
        std::size_t TotalSpawned_{0};
        std::size_t TotalReleased_{0};
        std::size_t TotalCancelled_{0};
        bool Cancelling_{false};
    };

    // ── template 实现 ─────────────────────────────────────────────

    template <typename Coro>
    auto TaskRegistry::SpawnTracked(std::string_view Label, Coro &&CoroObject) -> void
    {
        if (Cancelling_)
        {
            return;
        }

        auto Token = std::make_shared<TaskToken>(*this, Label);
        Tokens_.emplace(Token.get(), Token);
        ++TotalSpawned_;

        auto Completion = [Token](const std::exception_ptr &) noexcept { Token->Release(); };
        auto BoundCompletion = Net::bind_cancellation_slot(Token->CancellationSlot(), std::move(Completion));
        Net::co_spawn(Ioc_, std::forward<Coro>(CoroObject), std::move(BoundCompletion));
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

    inline auto TaskToken::RequestCancel() noexcept -> void
    {
        if (Released_ || CancelRequested_)
        {
            return;
        }
        CancelRequested_ = true;
        Cancellation_.emit(Net::cancellation_type::all);
    }

    inline auto TaskRegistry::Cancel() noexcept -> void
    {
        if (Cancelling_)
        {
            return;
        }
        Cancelling_ = true;

        // 取消回调可能立即推进 token 的完成路径，先复制 shared_ptr，避免
        // 发信号期间修改 Tokens_ 使迭代器失效。
        std::vector<std::shared_ptr<TaskToken>> Pending;
        Pending.reserve(Tokens_.size());
        for (const auto &[Pointer, Token] : Tokens_)
        {
            (void)Pointer;
            Pending.push_back(Token);
        }
        for (const auto &Token : Pending)
        {
            Token->RequestCancel();
        }
    }

    inline auto TaskRegistry::CancelAndWait(const std::chrono::milliseconds Timeout)
        -> Net::awaitable<bool>
    {
        Cancel();
        if (Tokens_.empty())
        {
            co_return true;
        }
        if (Timeout <= std::chrono::milliseconds::zero())
        {
            co_return false;
        }

        const auto Deadline = std::chrono::steady_clock::now() + Timeout;
        while (!Tokens_.empty())
        {
            DrainTimer_.expires_at(Deadline);
            boost::system::error_code Ec;
            co_await DrainTimer_.async_wait(Net::redirect_error(Net::use_awaitable, Ec));
            if (Tokens_.empty())
            {
                co_return true;
            }
            if (!Ec)
            {
                co_return false;
            }
        }

        co_return true;
    }

    inline auto TaskRegistry::Stats() const noexcept -> TaskStats
    {
        return TaskStats{Tokens_.size(), TotalSpawned_, TotalReleased_, TotalCancelled_};
    }

    inline auto TaskRegistry::ReleaseInternal(const TaskToken &Token) noexcept -> void
    {
        const auto It = Tokens_.find(&Token);
        if (It != Tokens_.end())
        {
            Tokens_.erase(It);
            if (Token.CancelRequested())
            {
                ++TotalCancelled_;
            }
            else
            {
                ++TotalReleased_;
            }
            if (Tokens_.empty())
            {
                DrainTimer_.cancel();
            }
        }
    }


} // namespace Preview::Coroutine
