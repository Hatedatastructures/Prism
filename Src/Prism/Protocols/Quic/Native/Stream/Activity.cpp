/**
 * @file Activity.cpp
 * @brief 原生 QUIC stream 操作回执和真实排空实现。
 */

#include <Prism/Protocols/Quic/Native/Stream/Activity.hpp>

#include <boost/asio/this_coro.hpp>

#include <memory>
#include <stdexcept>
#include <utility>

namespace Prism::Quic::Detail
{
    NativeStreamActivity::Operation::Operation(Operation&& Other) noexcept
        : Owner_(std::move(Other.Owner_)), Carrier_(std::move(Other.Carrier_)),
          Buffered_(std::exchange(Other.Buffered_, false)),
          Entered_(std::exchange(Other.Entered_, false))
    {
    }

    NativeStreamActivity::Operation::~Operation()
    {
        Carrier_.reset();
        if (Entered_ && Owner_)
        {
            if (Buffered_)
            {
                Owner_->BufferedReads_.Leave();
            }
            else
            {
                Owner_->Operations_.Leave();
            }
        }
    }

    NativeStreamActivity::Operation::Operation(
        std::shared_ptr<NativeStreamActivity> Owner,
        std::shared_ptr<void> Carrier,
        const bool Buffered)
        : Owner_(std::move(Owner)), Carrier_(std::move(Carrier)),
          Buffered_(Buffered), Entered_(true)
    {
    }

    NativeStreamActivity::CloseOperation::CloseOperation(CloseOperation&& Other) noexcept
        : Owner_(std::move(Other.Owner_)), Carrier_(std::move(Other.Carrier_)),
          Entered_(std::exchange(Other.Entered_, false))
    {
    }

    NativeStreamActivity::CloseOperation::~CloseOperation()
    {
        Carrier_.reset();
        if (Entered_ && Owner_)
        {
            Owner_->CloseActions_.Leave();
        }
    }

    NativeStreamActivity::CloseOperation::CloseOperation(
        std::shared_ptr<NativeStreamActivity> Owner,
        std::shared_ptr<void> Carrier)
        : Owner_(std::move(Owner)), Carrier_(std::move(Carrier)), Entered_(true)
    {
    }

    NativeStreamActivity::NativeStreamActivity(std::shared_ptr<StreamState> State)
        : State_(RequireState(std::move(State))),
          Context_(Prism::Executor::ContextOwner::Find(State_->Executor)),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(State_->Executor)),
          Operations_(Reclaimer_), BufferedReads_(Reclaimer_),
          CloseActions_(Reclaimer_), NativeTerminal_(Reclaimer_)
    {
        if (!NativeTerminal_.Enter())
        {
            NativeTerminal_.Block();
            return;
        }
        NativeTerminal_.Seal();
        if (State_->NativeTerminal.load(std::memory_order_acquire))
        {
            MarkNativeTerminal(State_->StreamCloseFailure);
        }
    }

    [[nodiscard]] auto NativeStreamActivity::BeginOperation(
        std::shared_ptr<void> Carrier) -> std::expected<Operation, Failure>
    {
        if (!Carrier)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!Operations_.Enter())
        {
            return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        return Operation(shared_from_this(), std::move(Carrier));
    }

    [[nodiscard]] auto NativeStreamActivity::BeginBufferedRead(
        std::shared_ptr<void> Carrier) -> std::expected<Operation, Failure>
    {
        if (!Carrier)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if ((!NativeTerminalSeen_.load(std::memory_order_acquire) &&
                !State_->NativeTerminal.load(std::memory_order_acquire)) ||
            !BufferedReads_.Enter())
        {
            return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        return Operation(shared_from_this(), std::move(Carrier), true);
    }

    [[nodiscard]] auto NativeStreamActivity::BeginClose(
        std::shared_ptr<void> Carrier) -> std::expected<CloseOperation, Failure>
    {
        if (!Carrier)
        {
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (CloseAccepted_.load(std::memory_order_acquire))
        {
            return CloseOperation{};
        }
        bool Open = false;
        if (!CloseClaimed_.compare_exchange_strong(Open, true, std::memory_order_acq_rel))
        {
            if (CloseAccepted_.load(std::memory_order_acquire))
            {
                return CloseOperation{};
            }
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        if (!CloseActions_.Enter())
        {
            CloseClaimed_.store(false, std::memory_order_release);
            return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        return CloseOperation(shared_from_this(), std::move(Carrier));
    }

    auto NativeStreamActivity::Seal() noexcept -> void
    {
        Operations_.Seal();
        BufferedReads_.Seal();
    }

    [[nodiscard]] auto NativeStreamActivity::IsRetired() const noexcept -> bool
    {
        return CloseAccepted_.load(std::memory_order_acquire) &&
               CloseDelivered_.load(std::memory_order_acquire) &&
               NativeTerminalSeen_.load(std::memory_order_acquire) &&
               Operations_.IsSealed() && Operations_.Active() == 0 && !Operations_.IsBlocked() &&
               BufferedReads_.IsSealed() && BufferedReads_.Active() == 0 && !BufferedReads_.IsBlocked() &&
               CloseActions_.IsSealed() && CloseActions_.Active() == 0 && !CloseActions_.IsBlocked() &&
               NativeTerminal_.IsSealed() && NativeTerminal_.Active() == 0 && !NativeTerminal_.IsBlocked();
    }

    auto NativeStreamActivity::CommitClose() noexcept -> void
    {
        Operations_.Seal();
        BufferedReads_.Seal();
        CloseAccepted_.store(true, std::memory_order_release);
        CloseActions_.Seal();
    }

    auto NativeStreamActivity::RollbackClose() noexcept -> void
    {
        if (!CloseAccepted_.load(std::memory_order_acquire))
        {
            CloseClaimed_.store(false, std::memory_order_release);
        }
    }

    auto NativeStreamActivity::CompleteClose(std::expected<void, Failure> Result) noexcept -> void
    {
        if (!Result)
        {
            Failure_.Record(Result.error());
        }
        BufferedReads_.Seal();
        CloseAccepted_.store(true, std::memory_order_release);
        CloseDelivered_.store(true, std::memory_order_release);
    }

    auto NativeStreamActivity::MarkNativeTerminal(Failure Reason) noexcept -> void
    {
        if (Reason.Failed())
        {
            Failure_.Record(Reason);
        }
        const auto FirstTerminal =
            !NativeTerminalSeen_.exchange(true, std::memory_order_acq_rel);
        Operations_.Seal();
        CloseActions_.Seal();
        CloseAccepted_.store(true, std::memory_order_release);
        CloseDelivered_.store(true, std::memory_order_release);
        if (FirstTerminal)
        {
            NativeTerminal_.Leave();
        }
    }

    [[nodiscard]] auto NativeStreamActivity::DrainOwned(
        std::shared_ptr<NativeStreamActivity> Owner)
        -> boost::asio::awaitable<std::expected<void, Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        if (Owner->State_->NativeTerminal.load(std::memory_order_acquire))
        {
            Owner->MarkNativeTerminal(Owner->State_->StreamCloseFailure);
        }
        if (!Owner->CloseAccepted_.load(std::memory_order_acquire) ||
            !Owner->CloseActions_.IsSealed())
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        Owner->BufferedReads_.Seal();
        const auto Operations = co_await Owner->Operations_.Drain();
        if (!Operations)
        {
            co_return std::unexpected(Operations.error());
        }
        const auto Close = co_await Owner->CloseActions_.Drain();
        if (!Close)
        {
            co_return std::unexpected(Close.error());
        }
        const auto BufferedReads = co_await Owner->BufferedReads_.Drain();
        if (!BufferedReads)
        {
            co_return std::unexpected(BufferedReads.error());
        }
        const auto CloseFailure = Owner->Failure_.Load();
        if (CloseFailure.Failed() &&
            !Owner->NativeTerminalSeen_.load(std::memory_order_acquire))
        {
            co_return std::unexpected(CloseFailure);
        }
        const auto Terminal = co_await Owner->NativeTerminal_.Drain();
        if (!Terminal)
        {
            co_return std::unexpected(Terminal.error());
        }
        if (!Owner->IsRetired())
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto FailureValue = Owner->Failure_.Load();
        if (FailureValue.Failed())
        {
            co_return std::unexpected(FailureValue);
        }
        co_return std::expected<void, Failure>{};
    }

    [[nodiscard]] auto NativeStreamActivity::RequireState(
        std::shared_ptr<StreamState> State) -> std::shared_ptr<StreamState>
    {
        if (!State)
        {
            throw std::invalid_argument("native stream activity requires a stream state");
        }
        return State;
    }
} // namespace Prism::Quic::Detail
