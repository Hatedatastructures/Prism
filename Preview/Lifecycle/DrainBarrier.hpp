/** @file DrainBarrier.hpp @brief 真实计数与显式失败的可等待屏障。 */
#pragma once
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Lifecycle/Detail/DrainNotification.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>
#include <utility>
namespace Preview::Lifecycle
{
    namespace Net = boost::asio;
    /** @brief Enter/Leave 可跨线程；通知使用线程安全 channel，不在归还路径分配投递动作。
     * @details 调用方保持 owner。取消、blocked 只返回失败，不清零 active；无半关闭。
     */
    class DrainBarrier final
    {
        struct State final
        {
            explicit State(std::shared_ptr<Preview::Executor::ExecutorReclaimer> Value)
                : ContextPin(Preview::Executor::ContextOwner::Find(Value->Executor())),
                  Reclaimer(std::move(Value)), Signal(Reclaimer->Executor(), 1),
                  Notification(Detail::DrainNotification::Bind(Reclaimer->Executor())) {}
            /** @brief 独立覆盖 drain awaitable 生命周期；最后释放 context service owner。 */
            std::shared_ptr<Preview::Executor::ContextOwner> ContextPin;
            std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
            Net::experimental::concurrent_channel<void(boost::system::error_code)> Signal;
            std::shared_ptr<const std::atomic<bool>> Notification;
            std::atomic<std::size_t> Active{0};
            std::atomic<bool> Sealed{false}, Blocked{false};
            auto Notify() -> void
            {
                if (Notification->load(std::memory_order_acquire))
                    (void)Signal.try_send(boost::system::error_code{});
            }
        };
    public:
        explicit DrainBarrier(std::shared_ptr<Preview::Executor::ExecutorReclaimer> Value)
            : State_(std::make_shared<State>(std::move(Value))) {}
        DrainBarrier(const DrainBarrier&) = delete;
        auto operator=(const DrainBarrier&) -> DrainBarrier& = delete;
        /** @brief 成功后调用者必须立即构造拥有型预约；拒绝不改变最终计数。 */
        [[nodiscard]] auto Enter() noexcept -> bool
        {
            if (State_->Sealed.load() || State_->Blocked.load()) return false;
            State_->Active.fetch_add(1);
            if (State_->Sealed.load() || State_->Blocked.load()) { Leave(); return false; }
            return true;
        }
        /** @brief 真实 owner 退栈后归还一次，最后一个归还者唤醒全部 drain 链。 */
        auto Leave() noexcept -> void
        {
            auto Count = State_->Active.load();
            while (Count != 0)
            {
                if (!State_->Active.compare_exchange_weak(Count, Count - 1)) continue;
                if (Count == 1) State_->Notify();
                return;
            }
        }
        auto Seal() noexcept -> void
        { State_->Sealed.store(true); }
        auto Block() noexcept -> void { State_->Blocked.store(true); State_->Notify(); }
        /** @brief 读取准入封止状态；已进入的预约仍必须真实归还。 */
        [[nodiscard]] auto IsSealed() const noexcept -> bool { return State_->Sealed.load(); }
        /** @brief 读取仍由实际 owner 持有的 drain 预约数。 */
        [[nodiscard]] auto Active() const noexcept -> std::size_t { return State_->Active.load(); }
        /** @brief 读取排空阻断状态；不改变真实 active 计数。 */
        [[nodiscard]] auto IsBlocked() const noexcept -> bool { return State_->Blocked.load(); }
        /** @brief 原 executor 驱动等待，零 active 才成功；不把 Blocked 当成完成。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        { return DrainState(State_); }
    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            while (!Value->Blocked.load() && Value->Active.load() != 0)
            {
                if (!Value->Reclaimer->CanDispatch())
                    co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                boost::system::error_code Error;
                co_await Value->Signal.async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    if (Value->Blocked.load() || Value->Active.load() == 0) Value->Notify();
                    co_return std::unexpected(Preview::Fault::FromNative(static_cast<std::error_code>(Error)));
                }
            }
            Value->Notify();
            if (Value->Blocked.load()) co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        std::shared_ptr<State> State_;
    };
}
