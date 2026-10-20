/** @file PreparedAction.cpp @brief 预建关闭动作与交付等待状态机实现。 */
#include <Prism/Foundation/Executor/PreparedAction.hpp>

#include <boost/asio/query.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <system_error>
#include <utility>

namespace Prism::Executor
{
    PreparedAction::NotificationLifetime::NotificationLifetime(
        boost::asio::execution_context& Context)
        : service(Context)
    {
    }

    auto PreparedAction::NotificationLifetime::shutdown() -> void
    {
        Active->store(false);
    }

    PreparedAction::Delivery::Delivery(std::shared_ptr<PreparedAction> Value)
        : Owner(std::move(Value))
    {
    }

    PreparedAction::Delivery::Delivery(Delivery&& Other) noexcept
        : Owner(std::move(Other.Owner))
    {
    }

    PreparedAction::Delivery::~Delivery()
    {
        if (!Owner) return;
        Owner->Queued_.store(false);
        if (!Executed)
        {
            Owner->Unavailable_.store(true);
            Owner->Storage_->Retain(Owner);
        }
        else Owner->Finished_.store(true);
        Owner->Notify();
    }

    auto PreparedAction::Delivery::operator()() -> void
    {
        Owner->Execute();
        Executed = true;
    }

    PreparedAction::PreparedAction(std::shared_ptr<ExecutorReclaimer> Reclaimer, Action Work)
        : Context_(ContextOwner::Find(Reclaimer->Executor())),
          Storage_(ContextOwner::Storage(Reclaimer->Executor())),
          Reclaimer_(std::move(Reclaimer)), Work_(std::move(Work)), Signal_(Reclaimer_->Executor(), 1),
          ContextActive_(boost::asio::use_service<NotificationLifetime>(
              boost::asio::query(Reclaimer_->Executor(), boost::asio::execution::context)).Active)
    {
    }

    auto PreparedAction::Submit() -> std::expected<void, Prism::Fault::Failure>
    {
        if (Done_.load(std::memory_order_acquire)) return Result();
        Storage_->Retain(shared_from_this());
        if (!Reclaimer_->CanDispatch())
        {
            Unavailable_.store(true);
            Notify();
            Storage_->Retain(shared_from_this());
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (Queued_.exchange(true)) return {};
        if (!Reclaimer_->Post(Delivery(shared_from_this())))
        {
            Unavailable_.store(true);
            Notify();
            Storage_->Retain(shared_from_this());
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return {};
    }

    auto PreparedAction::Result() const -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Done_.load(std::memory_order_acquire))
        {
            if (Unavailable_.load()) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
        }
        if (Failure_.Failed()) return std::unexpected(Failure_);
        return {};
    }

    auto PreparedAction::Notify() noexcept -> void
    {
        if (ContextActive_->load()) (void)Signal_.try_send(boost::system::error_code{});
    }

    auto PreparedAction::AwaitAction(std::shared_ptr<PreparedAction> Owner)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        co_await boost::asio::this_coro::reset_cancellation_state(boost::asio::disable_cancellation());
        while (!Owner->Finished_.load() && !Owner->Unavailable_.load())
        {
            boost::system::error_code Error;
            co_await Owner->Signal_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, Error));
            if (Error) co_return std::unexpected(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
        }
        Owner->Notify();
        if (!Owner->Finished_.load()) co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return Owner->Result();
    }

    auto PreparedAction::Execute() -> void
    {
        if (Retired_.load()) return;
        std::expected<void, Prism::Fault::Failure> Result;
        if (Work_) Result = Work_();
        if (!Result) Failure_ = Result.error();
        Done_.store(true, std::memory_order_release);
        if (!Result) return;
        Work_ = {};
        Retired_.store(true);
        Storage_->Collect();
    }
}
