/** @file FatalState.hpp @brief 原 execution_context 的不可恢复异常源和线程入口通知。 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/execution/context.hpp>
#include <boost/asio/query.hpp>
#include <atomic>
#include <exception>
#include <memory>
namespace Preview::Executor
{
    namespace Net = boost::asio;
    class FatalContext;
    /**
     * @brief 保存首个原 exception_ptr，不转换为业务Failure，也不在热完成回调中重抛。
     * @details For 是冷装配；Publish 不分配。Bind 必须在线程入口 run 前执行，
     *          外部io_context由调用者保活到全部真实Drain；服务shutdown解除借用。
     *          未绑定的异常仍由ProcessPending持原context的真实源，不静默丢弃。
     */
    class FatalState final
    {
    public:
        [[nodiscard]] static auto For(const Net::any_io_executor& Executor) -> std::shared_ptr<FatalState>;
        [[nodiscard]] static auto Bind(Net::io_context& Context) -> std::shared_ptr<FatalState>;
        auto Publish(std::exception_ptr Error) noexcept -> void
        {
            if (!Error) return;
            bool Empty = false;
            if (!Claimed_.compare_exchange_strong(Empty, true, std::memory_order_acq_rel)) return;
            Error_ = std::move(Error);
            Ready_.store(true, std::memory_order_release);
            if (auto* Origin = Origin_.load(std::memory_order_acquire)) Origin->stop();
            else
            {
                std::shared_ptr<FatalState> None;
                (void)ProcessPending_.compare_exchange_strong(None, Self_.lock(), std::memory_order_acq_rel);
            }
        }
        [[nodiscard]] auto HasFailure() const noexcept -> bool { return Ready_.load(std::memory_order_acquire); }
        /** @brief 完整原异常只由线程/进程入口读取，source owner必须继续存活。 */
        [[nodiscard]] auto Error() const noexcept -> std::exception_ptr
        { if (!HasFailure()) return {}; return Error_; }
        [[nodiscard]] static auto ProcessPending() noexcept -> std::shared_ptr<FatalState>
        { return ProcessPending_.load(std::memory_order_acquire); }
    private:
        friend class FatalContext;
        auto Detach() noexcept -> void { Origin_.store(nullptr, std::memory_order_release); }
        inline static std::atomic<std::shared_ptr<FatalState>> ProcessPending_;
        std::weak_ptr<FatalState> Self_;
        std::atomic<Net::io_context*> Origin_{nullptr};
        std::atomic<bool> Claimed_{false}, Ready_{false};
        std::exception_ptr Error_;
    };
    /** @brief 真实context的冷服务，仅关联fatal source，不查找协议或应用服务。 */
    class FatalContext final : public Net::execution_context::service
    {
    public:
        inline static Net::execution_context::id id;
        explicit FatalContext(Net::execution_context& Context) : service(Context), State(std::make_shared<FatalState>())
        { State->Self_ = State; }
        std::shared_ptr<FatalState> State;
    private:
        auto shutdown() -> void override { State->Detach(); }
    };
    inline auto FatalState::For(const Net::any_io_executor& Executor) -> std::shared_ptr<FatalState>
    {
        auto& Context = Net::query(Executor, Net::execution::context);
        return Net::use_service<FatalContext>(Context).State;
    }
    inline auto FatalState::Bind(Net::io_context& Context) -> std::shared_ptr<FatalState>
    {
        auto State = For(Context.get_executor());
        State->Origin_.store(&Context, std::memory_order_release);
        return State;
    }
}
