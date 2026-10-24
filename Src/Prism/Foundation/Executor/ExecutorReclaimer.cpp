/** @file ExecutorReclaimer.cpp @brief executor 回收交付 owner 实现。 */
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>

#include <boost/asio/strand.hpp>

namespace Prism::Executor
{
    auto ExecutorReclaimer::FindIo(const boost::asio::any_io_executor& Executor) noexcept
        -> boost::asio::io_context*
    {
        if (auto Value = Executor.target<boost::asio::io_context::executor_type>()) return &Value->context();
        if (auto Value = Executor.target<boost::asio::strand<boost::asio::any_io_executor>>())
            return FindIo(Value->get_inner_executor());
        if (auto Value = Executor.target<boost::asio::strand<boost::asio::io_context::executor_type>>())
            return &Value->get_inner_executor().context();
        return nullptr;
    }

    ExecutorReclaimer::State::State(boost::asio::any_io_executor Value)
        : Context(ContextOwner::Find(Value)), Executor(std::move(Value)),
          RegisteredContext(!Context.expired()), ExternalIo(FindIo(Executor))
    {
    }

    ExecutorReclaimer::PendingReservation::PendingReservation(std::shared_ptr<State> Value)
        : Owner(std::move(Value))
    {
        Owner->Pending.fetch_add(1);
    }

    ExecutorReclaimer::PendingReservation::PendingReservation(PendingReservation&& Other) noexcept
        : Owner(std::move(Other.Owner))
    {
    }

    ExecutorReclaimer::PendingReservation::~PendingReservation()
    {
        if (Owner) Owner->Pending.fetch_sub(1);
    }

    ExecutorReclaimer::ExecutorReclaimer(boost::asio::any_io_executor Value)
        : State_(std::make_shared<State>(std::move(Value)))
    {
    }

    auto ExecutorReclaimer::Quarantine() noexcept -> void
    {
        State_->Quarantined.store(true);
    }

    auto ExecutorReclaimer::CanDispatch() const noexcept -> bool
    {
        if (State_->Quarantined.load()) return false;
        if (!State_->RegisteredContext)
        {
            if (State_->ExternalIo) return !State_->ExternalIo->stopped();
            return true;
        }
        auto Context = State_->Context.lock();
        return Context && Context->CanDispatch();
    }
}
