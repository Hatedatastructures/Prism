/** @file ListenerConnectionDrain.cpp @brief 监听准入退役管理器实现。 */
#include <Prism/Runtime/ListenerConnectionDrain.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>

#include <system_error>
#include <utility>

namespace Prism::Runtime::Detail
{
    auto SessionAdmissionState::RetainSession(
        std::shared_ptr<Prism::Runtime::Session> Owner) noexcept -> void
    {
        SessionOwner.store(std::move(Owner), std::memory_order_release);
    }

    auto SessionAdmissionState::ReleaseSession() noexcept -> void
    {
        SessionOwner.store({}, std::memory_order_release);
    }

    ListenerConnectionDrain::ListenerConnectionDrain(Options Input)
        : Transport_(std::move(Input.Transport)),
          Reservation_(std::move(Input.Reservation)),
          CloseAction_(std::move(Input.CloseAction)),
          SessionState_(std::move(Input.SessionState)),
          Storage_(Transport_ ? Prism::Executor::ContextOwner::Storage(Transport_->Executor())
                              : Prism::Executor::ClosingStorage::ProcessStorage())
    {
        if (Transport_)
        {
            if (const auto Activity = Transport_->Activity())
            {
                Reclaimer_ = std::make_shared<Prism::Executor::ExecutorReclaimer>(
                    Activity->Executor());
            }
        }
    }

    auto ListenerConnectionDrain::MarkSessionStarted() noexcept -> void
    {
        if (SessionState_) SessionState_->Started.store(true, std::memory_order_release);
    }

    auto ListenerConnectionDrain::RetainSession(
        std::shared_ptr<Prism::Runtime::Session> SessionOwner) noexcept -> void
    {
        if (SessionState_) SessionState_->RetainSession(std::move(SessionOwner));
    }

    auto ListenerConnectionDrain::ConfigureSession(
        std::shared_ptr<Prism::Executor::PreparedAction> CloseAction,
        std::shared_ptr<SessionAdmissionState> SessionState) noexcept -> void
    {
        CloseAction_ = std::move(CloseAction);
        SessionState_ = std::move(SessionState);
    }

    auto ListenerConnectionDrain::Start() noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire) || HasTerminalSessionFailure()) return;
        StartOwner();
    }

    auto ListenerConnectionDrain::RequestRetirement() noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire) || HasTerminalSessionFailure()) return;
        if (Blocked_.exchange(false, std::memory_order_acq_rel))
            Started_.store(false, std::memory_order_release);
        Start();
    }

    auto ListenerConnectionDrain::IsRetired() const noexcept -> bool
    {
        return Retired_.load(std::memory_order_acquire);
    }

    auto ListenerConnectionDrain::IsDispatchUnavailable() const noexcept -> bool
    {
        return DispatchUnavailable_.load(std::memory_order_acquire);
    }

    auto ListenerConnectionDrain::MarkSessionDrained() noexcept -> void
    {
        if (!SessionState_) return;
        SessionState_->Drained.store(true, std::memory_order_release);
        RequestRetirement();
    }

    auto ListenerConnectionDrain::MarkSessionTerminalFailure(
        Prism::Fault::Failure Error) noexcept -> void
    {
        if (SessionState_ && SessionState_->Drained.load(std::memory_order_acquire)) return;
        if (SessionState_)
        {
            SessionState_->TerminalFailure.TrySet(Error);
            SessionState_->Terminal.store(true, std::memory_order_release);
            Error = SessionState_->TerminalFailure.Load();
        }
        Storage_->Retain(shared_from_this());
        StartOwner();
        Block(Error);
    }

    ListenerConnectionDrain::DispatchCompletion::DispatchCompletion(
        std::shared_ptr<ListenerConnectionDrain> Value,
        const std::uint64_t ValueGeneration) noexcept
        : Owner(std::move(Value)), Generation(ValueGeneration)
    {
    }

    ListenerConnectionDrain::DispatchCompletion::DispatchCompletion(
        DispatchCompletion&& Other) noexcept
        : Owner(std::move(Other.Owner)),
          Generation(Other.Generation),
          Error(std::move(Other.Error)),
          Invoked(Other.Invoked)
    {
    }

    ListenerConnectionDrain::DispatchCompletion::~DispatchCompletion() noexcept
    {
        if (!Owner) return;
        if (!Invoked) Owner->OnDispatchDropped(Generation);
        else Owner->OnDispatchCompleted(Generation, Error);
    }

    auto ListenerConnectionDrain::DispatchCompletion::operator()(
        std::exception_ptr Value) noexcept -> void
    {
        Invoked = true;
        Error = std::move(Value);
    }

    auto ListenerConnectionDrain::HasTerminalSessionFailure() const noexcept -> bool
    {
        if (!SessionState_) return false;
        return SessionState_->Terminal.load(std::memory_order_acquire);
    }

    auto ListenerConnectionDrain::StartOwner() noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire) || Started_.exchange(true)) return;
        try
        {
            const auto Owner = shared_from_this();
            Storage_->Retain(Owner);
            if (!Transport_ || !Transport_->Activity())
            {
                Block({Prism::Fault::Code::InvalidArgument});
                return;
            }
            const auto Generation = DispatchGeneration_.fetch_add(1, std::memory_order_acq_rel) + 1U;
            Net::co_spawn(Transport_->Activity()->Executor(), Run(Owner),
                DispatchCompletion(Owner, Generation));
        }
        catch (const std::system_error& Error)
        {
            const auto Failure = Prism::Fault::FromNative(Error.code());
            if (CanDispatch()) Block(Failure);
            else BlockDispatch(Failure);
        }
        catch (...)
        {
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            if (CanDispatch()) Block(Failure);
            else BlockDispatch(Failure);
        }
    }

    auto ListenerConnectionDrain::Run(std::shared_ptr<ListenerConnectionDrain> Owner)
        -> Net::awaitable<void>
    {
        try
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (Owner->SessionState_ && !Owner->HasTerminalSessionFailure() &&
                Owner->SessionState_->Started.load(std::memory_order_acquire) &&
                !Owner->SessionState_->Drained.load(std::memory_order_acquire))
            {
                Owner->WaitForSessionDrain();
                if (Owner->SessionState_->Drained.load(std::memory_order_acquire) ||
                    Owner->HasTerminalSessionFailure())
                {
                    Owner->RetryRequested_.store(true, std::memory_order_release);
                }
                co_return;
            }
            if (Owner->CloseAction_)
            {
                const auto Submitted = Owner->CloseAction_->Submit();
                if (!Submitted)
                {
                    if (Owner->CloseAction_->IsDispatchUnavailable())
                        Owner->BlockDispatch(Submitted.error());
                    else Owner->Block(Submitted.error());
                    co_return;
                }
                const auto Delivered = co_await Owner->CloseAction_->Await();
                if (!Delivered)
                {
                    if (Owner->CloseAction_->IsDispatchUnavailable())
                        Owner->BlockDispatch(Delivered.error());
                    else Owner->Block(Delivered.error());
                    co_return;
                }
            }
            else
            {
                const auto Canceled = Owner->Transport_->Cancel();
                const auto Closed = Owner->Transport_->Close();
                if (!Canceled)
                {
                    if (!Owner->CanDispatch()) Owner->BlockDispatch(Canceled.error());
                    else Owner->Block(Canceled.error());
                    co_return;
                }
                if (!Closed)
                {
                    if (!Owner->CanDispatch()) Owner->BlockDispatch(Closed.error());
                    else Owner->Block(Closed.error());
                    co_return;
                }
            }
            const auto Activity = Owner->Transport_->Activity();
            if (!Activity)
            {
                Owner->Block({Prism::Fault::Code::InvalidArgument});
                co_return;
            }
            const auto Drained = co_await Activity->Drain();
            // 同一传输已有物理退休回执时才接受关闭产生的取消结果。
            if (!Drained &&
                (Drained.error().Code != Prism::Fault::Code::Canceled ||
                 !Activity->IsRetired()))
            {
                if (!Owner->CanDispatch()) Owner->BlockDispatch(Drained.error());
                else Owner->Block(Drained.error());
                co_return;
            }
            if (Owner->HasTerminalSessionFailure())
            {
                Owner->BlockTerminal(Owner->SessionState_->TerminalFailure.Load());
                co_return;
            }
            if (Owner->SessionState_ && Owner->SessionState_->Started.load(std::memory_order_acquire) &&
                !Owner->SessionState_->Drained.load(std::memory_order_acquire))
            {
                Owner->WaitForSessionDrain();
                if (Owner->SessionState_->Drained.load(std::memory_order_acquire))
                    Owner->RetryRequested_.store(true, std::memory_order_release);
                co_return;
            }
            Owner->Completed_.store(true, std::memory_order_release);
        }
        catch (const std::system_error& Error)
        {
            const auto Failure = Prism::Fault::FromNative(Error.code());
            if (Owner->CanDispatch()) Owner->Block(Failure);
            else Owner->BlockDispatch(Failure);
        }
        catch (...)
        {
            const Prism::Fault::Failure Failure{Prism::Fault::Code::IoError};
            if (Owner->CanDispatch()) Owner->Block(Failure);
            else Owner->BlockDispatch(Failure);
        }
    }

    auto ListenerConnectionDrain::Block(Prism::Fault::Failure Error) noexcept -> void
    {
        if (Reservation_) Reservation_->BlockDrain();
        Failure_.TrySet(Error);
        Completed_.store(false, std::memory_order_release);
        Blocked_.store(true, std::memory_order_release);
        Started_.store(false, std::memory_order_release);
    }

    auto ListenerConnectionDrain::BlockDispatch(Prism::Fault::Failure Error) noexcept -> void
    {
        DispatchUnavailable_.store(true, std::memory_order_release);
        Storage_->Retain(shared_from_this());
        Block(Error);
    }

    auto ListenerConnectionDrain::BlockTerminal(Prism::Fault::Failure Error) noexcept -> void
    {
        Block(Error);
    }

    auto ListenerConnectionDrain::WaitForSessionDrain() noexcept -> void
    {
        Completed_.store(false, std::memory_order_release);
        Started_.store(false, std::memory_order_release);
    }

    auto ListenerConnectionDrain::OnDispatchDropped(const std::uint64_t Generation) noexcept -> void
    {
        if (Generation == DispatchGeneration_.load(std::memory_order_acquire) &&
            !Retired_.load(std::memory_order_acquire))
            BlockDispatch({Prism::Fault::Code::Blocked});
    }

    auto ListenerConnectionDrain::OnDispatchCompleted(
        const std::uint64_t Generation,
        const std::exception_ptr& Error) noexcept -> void
    {
        if (Generation != DispatchGeneration_.load(std::memory_order_acquire) ||
            Retired_.load(std::memory_order_acquire))
            return;
        if (Error)
        {
            try
            {
                std::rethrow_exception(Error);
            }
            catch (const std::system_error& Native)
            {
                Block(Prism::Fault::FromNative(Native.code()));
            }
            catch (...)
            {
                Block({Prism::Fault::Code::IoError});
            }
            return;
        }
        if (!Completed_.load(std::memory_order_acquire))
        {
            if (RetryRequested_.exchange(false, std::memory_order_acq_rel)) RequestRetirement();
            return;
        }
        if (SessionState_) SessionState_->ReleaseSession();
        Retired_.store(true, std::memory_order_release);
        if (Reservation_) Reservation_->Release();
        Storage_->Collect();
    }
}
