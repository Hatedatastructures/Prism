/** @file DrainBarrier.cpp @brief drain 屏障计数、通知与等待实现。 */
#include <Prism/Lifecycle/DrainBarrier.hpp>

#include <Prism/Foundation/Executor/ContextOwner.hpp>

#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Lifecycle
{
    struct DrainBarrier::State final
    {
        explicit State(std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value)
            : ContextPin(Prism::Executor::ContextOwner::Find(Value->Executor())),
              Reclaimer(std::move(Value)), Signal(Reclaimer->Executor(), 1),
              Notification(BindDrainNotification(Reclaimer->Executor())) {}

        /** @brief 独立覆盖 drain awaitable 生命周期；最后释放 context service owner。 */
        std::shared_ptr<Prism::Executor::ContextOwner> ContextPin;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
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

    DrainBarrier::DrainBarrier(std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value)
        : State_(std::make_shared<State>(std::move(Value))) {}

    DrainBarrier::~DrainBarrier() = default;

    auto DrainBarrier::Enter() noexcept -> bool
    {
        if (State_->Sealed.load() || State_->Blocked.load()) return false;
        State_->Active.fetch_add(1);
        if (State_->Sealed.load() || State_->Blocked.load())
        {
            Leave();
            return false;
        }
        return true;
    }

    auto DrainBarrier::Leave() noexcept -> void
    {
        auto Count = State_->Active.load();
        while (Count != 0)
        {
            if (!State_->Active.compare_exchange_weak(Count, Count - 1)) continue;
            if (Count == 1) State_->Notify();
            return;
        }
    }

    auto DrainBarrier::Seal() noexcept -> void
    {
        State_->Sealed.store(true);
    }

    auto DrainBarrier::Block() noexcept -> void
    {
        State_->Blocked.store(true);
        State_->Notify();
    }

    auto DrainBarrier::IsSealed() const noexcept -> bool
    {
        return State_->Sealed.load();
    }

    auto DrainBarrier::Active() const noexcept -> std::size_t
    {
        return State_->Active.load();
    }

    auto DrainBarrier::IsBlocked() const noexcept -> bool
    {
        return State_->Blocked.load();
    }

    auto DrainBarrier::Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return DrainState(State_);
    }

    auto DrainBarrier::DrainState(std::shared_ptr<State> Value)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        while (!Value->Blocked.load() && Value->Active.load() != 0)
        {
            if (!Value->Reclaimer->CanDispatch())
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            boost::system::error_code Error;
            co_await Value->Signal.async_receive(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                if (Value->Blocked.load() || Value->Active.load() == 0) Value->Notify();
                co_return std::unexpected(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
            }
        }
        Value->Notify();
        if (Value->Blocked.load())
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    DrainReservation::DrainReservation(DrainBarrier& Barrier)
        : Barrier_(&Barrier)
    {
    }

    DrainReservation::DrainReservation(DrainReservation&& Other) noexcept
        : Barrier_(std::exchange(Other.Barrier_, nullptr))
    {
    }

    DrainReservation::~DrainReservation()
    {
        if (Barrier_) Barrier_->Leave();
    }

    auto DrainReservation::Transfer() noexcept -> void
    {
        Barrier_ = nullptr;
    }
}
