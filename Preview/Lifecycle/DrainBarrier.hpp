/**
 * @file DrainBarrier.hpp
 * @brief 基于真实 active 计数的异步排空屏障
 * @details Drain 只有在计数降为零时才完成，不使用固定延迟或 grace timer。
 *          通知由绑定 executor 串行执行；单槽 channel 在多个等待者之间
 *          传递同一个零计数事件，不建立无界等待队列。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>

#include <Preview/Resource/ExecutorReclaimer.hpp>

namespace Preview::Lifecycle
{

    namespace Net = boost::asio;

    class DrainBarrier final
    {
    private:
        using Completion = Net::experimental::channel<void(boost::system::error_code)>;

        struct State final
        {
            explicit State(std::shared_ptr<Preview::Resource::ExecutorReclaimer> ReclaimerValue)
                : Reclaimer(std::move(ReclaimerValue)), Signal(Reclaimer->Executor(), 1)
            {
            }

            auto NotifyZero() -> void
            {
                if (Active.load(std::memory_order_acquire) != 0 &&
                    !Blocked.load(std::memory_order_acquire))
                {
                    return;
                }
                (void)Signal.try_send(boost::system::error_code{});
            }

            std::shared_ptr<Preview::Resource::ExecutorReclaimer> Reclaimer;
            Completion Signal;
            std::atomic<std::size_t> Active{0};
            std::atomic<bool> Sealed{false};
            std::atomic<bool> Blocked{false};
        };

    public:
        explicit DrainBarrier(std::shared_ptr<Preview::Resource::ExecutorReclaimer> Reclaimer)
            : State_(std::make_shared<State>(std::move(Reclaimer)))
        {
        }

        DrainBarrier(const DrainBarrier &) = delete;
        auto operator=(const DrainBarrier &) -> DrainBarrier & = delete;
        DrainBarrier(DrainBarrier &&) = delete;
        auto operator=(DrainBarrier &&) -> DrainBarrier & = delete;

        /**
         * @brief 增加一个待排空节点
         * @return 屏障未封止且成功计数返回 true
         */
        [[nodiscard]] auto Enter() noexcept -> bool
        {
            if (State_->Sealed.load(std::memory_order_acquire) ||
                State_->Blocked.load(std::memory_order_acquire))
            {
                return false;
            }
            State_->Active.fetch_add(1, std::memory_order_acq_rel);
            if (State_->Sealed.load(std::memory_order_acquire))
            {
                const auto Remaining = State_->Active.fetch_sub(1, std::memory_order_acq_rel) - 1;
                if (Remaining == 0)
                {
                    const auto StateValue = State_;
                    if (!State_->Reclaimer->Post([StateValue] { StateValue->NotifyZero(); }))
                    {
                        State_->Blocked.store(true, std::memory_order_release);
                        (void)State_->Signal.try_send(boost::system::error_code{});
                    }
                }
                return false;
            }
            return true;
        }

        /**
         * @brief 释放一个待排空节点
         * @details 只有从 1 变为 0 时才发送一次零计数通知。
         */
        auto Leave() noexcept -> void
        {
            auto Previous = State_->Active.load(std::memory_order_acquire);
            for (;;)
            {
                if (Previous == 0)
                {
                    return;
                }
                if (State_->Active.compare_exchange_weak(
                        Previous, Previous - 1, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    break;
                }
            }
            const auto Remaining = Previous - 1;
            if (Remaining != 0)
            {
                return;
            }
            const auto StateValue = State_;
            if (!StateValue->Reclaimer->Post([StateValue] { StateValue->NotifyZero(); }))
            {
                Block();
            }
        }

        /**
         * @brief 封止新节点
         * @details 封止不改变当前计数，既有节点仍需真实完成。
         */
        auto Seal() noexcept -> void
        {
            if (State_->Sealed.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            if (State_->Active.load(std::memory_order_acquire) == 0)
            {
                const auto StateValue = State_;
                if (!State_->Reclaimer->Post([StateValue] { StateValue->NotifyZero(); }))
                {
                    Block();
                }
            }
        }

        /**
         * @brief 标记排空无法继续，并唤醒当前等待者
         * @details 当 executor 投递失败时，继续等待零计数没有进展保证；
         *          显式 blocked 状态让上层可以报告不完整收口而不永久挂起。
         */
        auto Block() noexcept -> void
        {
            State_->Blocked.store(true, std::memory_order_release);
            (void)State_->Signal.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto IsSealed() const noexcept -> bool
        {
            return State_->Sealed.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Active() const noexcept -> std::size_t
        {
            return State_->Active.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsBlocked() const noexcept -> bool
        {
            return State_->Blocked.load(std::memory_order_acquire);
        }

        /**
         * @brief 异步等待实际 active 计数归零
         * @note 必须由关联 executor 驱动；不阻塞线程，也不使用 grace delay。
         */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            return DrainState(State_);
        }

    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> StateValue)
            -> Net::awaitable<void>
        {
            const auto Executor = StateValue->Reclaimer->Executor();
            co_await Net::dispatch(Executor, Net::use_awaitable);
            if (StateValue->Blocked.load(std::memory_order_acquire) ||
                StateValue->Active.load(std::memory_order_acquire) == 0)
            {
                co_return;
            }

            while (!StateValue->Blocked.load(std::memory_order_acquire) &&
                   StateValue->Active.load(std::memory_order_acquire) != 0)
            {
                boost::system::error_code ErrorCode;
                co_await StateValue->Signal.async_receive(
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
            (void)StateValue->Signal.try_send(boost::system::error_code{});
        }

        std::shared_ptr<State> State_;
    };

} // namespace Preview::Lifecycle
