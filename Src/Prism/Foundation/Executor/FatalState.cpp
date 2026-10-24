/** @file FatalState.cpp @brief 原 execution_context 的异常源实现。 */
#include <Prism/Foundation/Executor/FatalState.hpp>

#include <boost/asio/query.hpp>
#include <boost/asio/execution_context.hpp>
#include <utility>

namespace Prism::Executor
{
    auto FatalState::Publish(std::exception_ptr Error) noexcept -> void
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

    auto FatalState::Detach() noexcept -> void
    {
        Origin_.store(nullptr, std::memory_order_release);
    }

    FatalContext::FatalContext(Net::execution_context& Context)
        : service(Context), State(std::make_shared<FatalState>())
    {
        State->Self_ = State;
    }

    auto FatalContext::shutdown() -> void
    {
        State->Detach();
    }

    auto FatalState::For(const Net::any_io_executor& Executor) -> std::shared_ptr<FatalState>
    {
        auto& Context = Net::query(Executor, Net::execution::context);
        return Net::use_service<FatalContext>(Context).State;
    }

    auto FatalState::Bind(Net::io_context& Context) -> std::shared_ptr<FatalState>
    {
        auto State = For(Context.get_executor());
        State->Origin_.store(&Context, std::memory_order_release);
        return State;
    }
}
