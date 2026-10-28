/** @file Attempt.cpp @brief Provider drain attempt 并发回执实现。 */

#include <Prism/Protocols/Common/Provider/Drain/Attempt.hpp>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Protocols::Detail
{
    auto PreserveProviderDrainFailure(
        Prism::Fault::Failure& Primary,
        const Prism::Fault::Failure& Secondary) noexcept -> void
    {
        if (Secondary.Succeeded()) return;
        const bool PrimaryIsRetryableCancellation =
            Primary.Code == Prism::Fault::Code::Canceled;
        const bool SecondaryIsDurable =
            Secondary.Code != Prism::Fault::Code::Canceled;
        if (Primary.Succeeded() || (PrimaryIsRetryableCancellation && SecondaryIsDurable))
            Primary = Secondary;
    }

    [[nodiscard]] auto ProviderDrainAwaitFailure(
        const std::exception_ptr& Exception) noexcept -> Prism::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error& Failure)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Failure.code()));
        }
        catch (const std::system_error& Failure)
        {
            return Prism::Fault::FromNative(Failure.code());
        }
        catch (...)
        {
            return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        }
        return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
    }

    ProviderSessionDrainAttempt::ProviderSessionDrainAttempt()
        : ClosedSentinel_(std::make_shared<WaiterNode>())
    {
    }

    auto ProviderSessionDrainAttempt::Publish(Result Value) noexcept -> void
    {
        bool Idle = false;
        if (!Publishing_.compare_exchange_strong(
                Idle, true, std::memory_order_acq_rel, std::memory_order_acquire)) return;
        Result_ = std::move(Value);
        auto Current = Waiters_.exchange(ClosedSentinel_, std::memory_order_acq_rel);
        if (Current == ClosedSentinel_) return;
        while (Current)
        {
            if (const auto Value = Current->Value.lock()) Notify(Value);
            Current = std::move(Current->Next);
        }
    }

    [[nodiscard]] auto ProviderSessionDrainAttempt::PublishedResult() const -> Result
    {
        if (!IsPublished())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return Result_;
    }

    auto ProviderSessionDrainAttempt::RegisterWaiter(
        const std::shared_ptr<Waiter>& Value) -> bool
    {
        auto Current = Waiters_.load(std::memory_order_acquire);
        auto Node = std::make_shared<WaiterNode>();
        Node->Value = Value;
        while (Current != ClosedSentinel_)
        {
            Node->Next = Current;
            if (Waiters_.compare_exchange_weak(Current, Node,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto ProviderSessionDrainAttempt::WaitPinned(
        std::shared_ptr<ProviderSessionDrainAttempt> Self) -> Net::awaitable<Result>
    {
        try
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        }
        catch (...)
        {
            if (Self->IsPublished()) co_return Self->PublishedResult();
            co_return std::unexpected(ProviderDrainAwaitFailure(std::current_exception()));
        }
        std::shared_ptr<Waiter> Waiting;
        try
        {
            const auto Executor = co_await Net::this_coro::executor;
            Waiting = std::make_shared<Waiter>(Executor);
            if (!Self->RegisterWaiter(Waiting)) co_return Self->PublishedResult();
        }
        catch (...)
        {
            if (Self->IsPublished()) co_return Self->PublishedResult();
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }

        boost::system::error_code Error;
        try
        {
            co_await Waiting->Events.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
        }
        catch (const boost::system::system_error& Failure)
        {
            if (Self->IsPublished()) co_return Self->PublishedResult();
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Failure.code())));
        }
        catch (const std::system_error& Failure)
        {
            if (Self->IsPublished()) co_return Self->PublishedResult();
            co_return std::unexpected(Prism::Fault::FromNative(Failure.code()));
        }
        catch (...)
        {
            if (Self->IsPublished()) co_return Self->PublishedResult();
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (Error && !Self->IsPublished())
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
        }
        co_return Self->PublishedResult();
    }

    auto ProviderSessionDrainAttempt::Notify(
        const std::shared_ptr<Waiter>& Value) noexcept -> void
    {
        try { (void)Value->Events.try_send(boost::system::error_code{}); }
        catch (...) { try { Value->Events.close(); } catch (...) {} }
    }

    ProviderSessionDrainCoordinator::DrainTurn::DrainTurn(
        std::shared_ptr<ProviderSessionDrainAttempt> Value,
        const bool Owner,
        ProviderSessionDrainAttempt::Result ResultValue) noexcept
        : Value_(std::move(Value)), Result_(std::move(ResultValue)), Owner_(Owner)
    {
    }

    ProviderSessionDrainCoordinator::DrainTurn::DrainTurn(
        DrainTurn&& Other) noexcept
        : Value_(std::move(Other.Value_)), Result_(std::move(Other.Result_)),
          Owner_(std::exchange(Other.Owner_, false))
    {
    }

    ProviderSessionDrainCoordinator::DrainTurn::~DrainTurn() noexcept
    {
        Publish();
    }

    auto ProviderSessionDrainCoordinator::DrainTurn::SetResult(
        ProviderSessionDrainAttempt::Result Value) noexcept -> void
    {
        Result_ = std::move(Value);
    }

    auto ProviderSessionDrainCoordinator::DrainTurn::Publish() noexcept -> void
    {
        if (Owner_)
        {
            Owner_ = false;
            Value_->Publish(std::move(Result_));
        }
    }

    auto ProviderSessionDrainCoordinator::SignalOwnerClose() noexcept -> bool
    {
        return Signal(OwnerCloseBit, AcceptAttemptCompleteBit);
    }

    auto ProviderSessionDrainCoordinator::SignalAcceptAttemptComplete() noexcept -> bool
    {
        return Signal(AcceptAttemptCompleteBit,
            static_cast<std::uint8_t>(OwnerCloseBit | MuxRootRetirementBit));
    }

    auto ProviderSessionDrainCoordinator::SignalMuxRootRetirement() noexcept -> bool
    {
        return Signal(MuxRootRetirementBit, AcceptAttemptCompleteBit);
    }

    [[nodiscard]] auto ProviderSessionDrainCoordinator::Acquire()
        -> Net::awaitable<std::expected<DrainTurn, Prism::Fault::Failure>>
    {
        try
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            while (true)
            {
                auto Current = Current_.load(std::memory_order_acquire);
                if (Current && !Current->IsPublished())
                {
                    const auto Waited = co_await Current->Wait();
                    if (!Waited) co_return std::unexpected(Waited.error());
                    co_return DrainTurn{std::move(Current), false, Waited};
                }
                std::shared_ptr<ProviderSessionDrainAttempt> Candidate;
                try { Candidate = std::make_shared<ProviderSessionDrainAttempt>(); }
                catch (...)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                }
                if (Current_.compare_exchange_weak(Current, Candidate,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    co_return DrainTurn{std::move(Candidate), true,
                        std::unexpected(
                            Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
                }
            }
        }
        catch (...)
        {
            co_return std::unexpected(ProviderDrainAwaitFailure(std::current_exception()));
        }
    }

    auto ProviderSessionDrainCoordinator::Signal(
        const std::uint8_t Bit,
        const std::uint8_t TriggerMask) noexcept -> bool
    {
        const auto Previous = RetirementSignals_.fetch_or(Bit, std::memory_order_acq_rel);
        return (Previous & TriggerMask) != 0U;
    }
} // namespace Prism::Protocols::Detail
