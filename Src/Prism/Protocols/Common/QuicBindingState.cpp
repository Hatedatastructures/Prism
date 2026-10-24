/** @file QuicBindingState.cpp @brief QUIC owner 集合关闭与退休状态实现。 */

#include <Prism/Protocols/Common/QuicBindingState.hpp>

#include <Prism/Foundation/Executor/ContextOwner.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <memory>
#include <utility>

namespace Prism::Protocols
{
    QuicBindingState::QuicBindingState(boost::asio::any_io_executor Executor)
        : Context_(Prism::Executor::ContextOwner::Find(Executor)),
          Storage_(Prism::Executor::ContextOwner::Storage(Executor)),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor))),
          Barrier_(Reclaimer_)
    {
    }

    [[nodiscard]] auto QuicBindingState::Track(
        std::shared_ptr<Prism::Contract::QuicConnectionOwner> Owner) -> bool
    {
        if (Closed_.load() || !CanAdmit() || !Barrier_.Enter()) return false;
        try
        {
            Connections_.push_back(std::move(Owner));
            Active_.fetch_add(1);
        }
        catch (...)
        {
            Barrier_.Leave();
            throw;
        }
        return true;
    }

    auto QuicBindingState::Finished(
        const Prism::Contract::QuicConnectionOwner* Owner) noexcept -> void
    {
        const auto Found = std::find_if(Connections_.begin(), Connections_.end(),
            [Owner](const auto& Value) { return Value.get() == Owner; });
        if (Found == Connections_.end()) return;
        Connections_.erase(Found);
        Active_.fetch_sub(1);
        Barrier_.Leave();
    }

    [[nodiscard]] auto QuicBindingState::PendingCloseFailure() const noexcept
        -> std::optional<Prism::Fault::Failure>
    {
        return LoadCloseFailure();
    }

    [[nodiscard]] auto QuicBindingState::CanDispatch() const noexcept -> bool
    {
        return (!Context_ || Context_->CanDispatch()) && Reclaimer_->CanDispatch();
    }

    [[nodiscard]] auto QuicBindingState::CanAdmit() const noexcept -> bool
    {
        auto Storage = Storage_.lock();
        return CanDispatch() && (!Storage || !Storage->IsSealed());
    }

    auto QuicBindingState::Close() noexcept -> void
    {
        if (Closed_.exchange(true)) return;
        Barrier_.Seal();
        RequestRetirement();
    }

    auto QuicBindingState::Failed(Prism::Fault::Failure Reason) noexcept -> void
    {
        if (Reason.Succeeded()) Reason = {Prism::Fault::Code::Blocked};
        Failure_.TrySet(Reason);
        DispatchFailed_.store(Reason.Code == Prism::Fault::Code::Blocked);
        Closed_.store(true);
        Barrier_.Seal();
        Barrier_.Block();
        HoldPending();
    }

    auto QuicBindingState::HoldPending() noexcept -> void
    {
        if (Active_.load() != 0)
        {
            if (auto Storage = Storage_.lock()) Storage->Retain(shared_from_this());
        }
    }

    auto QuicBindingState::RetainRejectedCloseRequest(
        Prism::Fault::Failure Reason) noexcept -> void
    {
        if (Reason.Succeeded()) Reason = {Prism::Fault::Code::Blocked};
        SaveCloseFailure(Reason);
        HoldPending();
    }

    auto QuicBindingState::RequestRetirement() noexcept -> void
    {
        const auto Weak = weak_from_this();
        if (!CanDispatch())
        {
            SaveCloseFailure({Prism::Fault::Code::Blocked});
            DispatchFailed_.store(true);
            HoldPending();
            return;
        }
        const auto Posted = Reclaimer_->Post([Weak]
        {
            if (auto State = Weak.lock())
            {
                const auto Result = State->CloseOnExecutor();
                if (!Result) State->SaveCloseFailure(Result.error());
            }
        });
        if (!Posted)
        {
            SaveCloseFailure(Posted.error());
            DispatchFailed_.store(true);
            HoldPending();
        }
    }

    [[nodiscard]] auto QuicBindingState::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Close();
        if (!CanDispatch())
        {
            const auto Failure = Failure_.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            const auto CloseFailure = LoadCloseFailure();
            if (CloseFailure) co_return std::unexpected(*CloseFailure);
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_await boost::asio::dispatch(Reclaimer_->Executor(), boost::asio::use_awaitable);
        const auto CloseResult = CloseOnExecutor();
        if (!CloseResult) co_return std::unexpected(CloseResult.error());
        const auto Drained = co_await Barrier_.Drain();
        if (!Drained)
        {
            const auto Failure = Failure_.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::unexpected(Drained.error());
        }
        const auto Failure = Failure_.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto QuicBindingState::CloseOnExecutor()
        -> std::expected<void, Prism::Fault::Failure>
    {
        auto FirstFailure = std::optional<Prism::Fault::Failure>{};
        for (const auto& Owner : Connections_)
        {
            const auto Result = Owner->RequestClose();
            if (!Result && !FirstFailure) FirstFailure = Result.error();
        }
        if (FirstFailure)
        {
            SaveCloseFailure(*FirstFailure);
            return std::unexpected(LoadCloseFailure().value_or(*FirstFailure));
        }
        ClearCloseFailure();
        return {};
    }

    auto QuicBindingState::SaveCloseFailure(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
        if (CloseFailure_.load(std::memory_order_acquire)) return;
        try
        {
            auto Stored = std::make_shared<const Prism::Fault::Failure>(Failure);
            std::shared_ptr<const Prism::Fault::Failure> Empty;
            (void)CloseFailure_.compare_exchange_strong(
                Empty, std::move(Stored), std::memory_order_acq_rel);
        }
        catch (...)
        {
            DispatchFailed_.store(true);
        }
    }

    [[nodiscard]] auto QuicBindingState::LoadCloseFailure() const noexcept
        -> std::optional<Prism::Fault::Failure>
    {
        const auto Failure = CloseFailure_.load(std::memory_order_acquire);
        if (!Failure) return std::nullopt;
        return *Failure;
    }

    auto QuicBindingState::ClearCloseFailure() noexcept -> void
    {
        CloseFailure_.store({}, std::memory_order_release);
    }
} // namespace Prism::Protocols
