/** @file BindingLifetime.cpp @brief 协议绑定真实 carrier 生命周期实现。 */

#include <Prism/Protocols/Common/BindingLifetime.hpp>

#include <Prism/Foundation/Error.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/strand.hpp>

#include <exception>
#include <memory>
#include <utility>

namespace Prism::Protocols
{
    BindingLifetime::CloseState::CloseState(
        Net::any_io_executor Executor,
        Prism::Foundation::GenerationPin Pin)
        : Generation(std::move(Pin)), Context(Prism::Executor::ContextOwner::Find(Executor)),
          Storage(Prism::Executor::ContextOwner::Storage(Executor)),
          Barrier(std::make_shared<Prism::Executor::ExecutorReclaimer>(
              Net::make_strand(std::move(Executor))))
    {
    }

    BindingLifetime::Activity::Activity(
        std::shared_ptr<CloseState> State,
        Prism::SharedTransmission Carrier)
        : State_(std::move(State)), Carrier_(std::move(Carrier)),
          Executor_(Carrier_.load()->Executor()),
          Context_(Prism::Executor::ContextOwner::Find(Executor_)), Reclaimer_(Executor_)
    {
    }

    BindingLifetime::Activity::~Activity()
    {
        State_->Barrier.Leave();
    }

    auto BindingLifetime::Activity::Attach(std::shared_ptr<ClosingSlot> Slot) -> void
    {
        Slot_ = Slot;
        Slot->Storage = Prism::Executor::ContextOwner::Storage(Executor_);
    }

    auto BindingLifetime::Activity::AttachCloseReceipt(
        std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt) noexcept -> void
    {
        CloseReceipt_.store(std::move(Receipt), std::memory_order_release);
        if (const auto Slot = Slot_.lock()) Slot->Activated.store(true, std::memory_order_release);
    }

    [[nodiscard]] auto BindingLifetime::Activity::RequestClose() noexcept
        -> Prism::Transmission::ControlResult
    {
        if (Retired_.load(std::memory_order_acquire)) return {};
        if (CloseRequested_.exchange(true, std::memory_order_acq_rel))
        {
            const auto Failure = State_->Failure.Load();
            if (Failure.Failed()) return std::unexpected(Failure);
            return {};
        }
        return DispatchClose(Slot_.lock());
    }

    auto BindingLifetime::Activity::EndIo() noexcept -> void
    {
        if (IoActive_.fetch_sub(1) == 1)
        {
            if (Retired_.load()) Carrier_.store({});
            ReleaseFailedSlot(Slot_.lock());
        }
    }

    auto BindingLifetime::Activity::RequestRetirement() noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire)) return;
        const auto Slot = Slot_.lock();
        if (!Slot) return;
        const bool DispatchFailed = Slot->DispatchFailed.load(std::memory_order_acquire);
        const bool RetryPending = Slot->RetryPending.exchange(false, std::memory_order_acq_rel);
        if (!DispatchFailed && !RetryPending) return;
        (void)DispatchClose(Slot);
    }

    auto BindingLifetime::Activity::ReleaseBinding() noexcept -> void
    {
        const auto Slot = Slot_.lock();
        if (!Slot || (Retired_.load() && IoActive_.load() == 0)) return;
        Slot->Failed.store(shared_from_this());
        if (auto Storage = Slot->Storage.lock()) Storage->Retain(Slot);
        (void)RequestClose();
    }

    [[nodiscard]] auto BindingLifetime::Activity::DispatchClose(
        const std::shared_ptr<ClosingSlot>& Slot) noexcept
        -> Prism::Transmission::ControlResult
    {
        if (Retired_.load(std::memory_order_acquire)) return {};
        if (CloseInFlight_.exchange(true, std::memory_order_acq_rel))
        {
            const auto Failure = State_->Failure.Load();
            if (Failure.Failed()) return std::unexpected(Failure);
            return {};
        }
        if (!CanDispatch())
        {
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            CloseInFlight_.store(false, std::memory_order_release);
            if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
            HoldFailure(Failure, Slot);
            return std::unexpected(Failure);
        }
        try
        {
            if (Slot) Slot->DispatchFailed.store(false, std::memory_order_release);
            const auto Self = shared_from_this();
            const auto Posted = Reclaimer_.Post(
                [Self, Slot] { Self->StartCloseOnExecutor(Slot); });
            if (!Posted)
            {
                CloseInFlight_.store(false, std::memory_order_release);
                if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
                HoldFailure(Posted.error(), Slot);
                return std::unexpected(Posted.error());
            }
            return {};
        }
        catch (...)
        {
            CloseInFlight_.store(false, std::memory_order_release);
            if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
            PublishFatal(std::current_exception(), Slot);
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto BindingLifetime::Activity::HoldFailure(
        Prism::Fault::Failure Reason,
        const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
    {
        if (Reason.Succeeded()) Reason = {Prism::Fault::Code::Blocked};
        State_->Failure.TrySet(Reason);
        if (!Slot)
        {
            State_->Barrier.Block();
            return;
        }
        Slot->RetryPending.store(true, std::memory_order_release);
        Slot->Failed.store(shared_from_this());
        if (auto Storage = Slot->Storage.lock()) Storage->Retain(Slot);
        State_->Barrier.Block();
    }

    auto BindingLifetime::Activity::StartCloseOnExecutor(
        const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
    {
        try
        {
            const auto Self = shared_from_this();
            Net::co_spawn(Executor_, Self->CloseAndDrain(),
                [Self, Slot](std::exception_ptr Error,
                    Prism::Transmission::ControlResult Result)
                { Self->CompleteClose(std::move(Error), std::move(Result), Slot); });
        }
        catch (...)
        {
            CloseInFlight_.store(false, std::memory_order_release);
            if (Slot) Slot->DispatchFailed.store(true, std::memory_order_release);
            PublishFatal(std::current_exception(), Slot);
        }
    }

    auto BindingLifetime::Activity::CompleteClose(
        std::exception_ptr Error,
        Prism::Transmission::ControlResult Result,
        const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
    {
        if (Error)
        {
            CloseInFlight_.store(false, std::memory_order_release);
            PublishFatal(std::move(Error), Slot);
            return;
        }
        if (!Result)
        {
            CloseInFlight_.store(false, std::memory_order_release);
            HoldFailure(Result.error(), Slot);
            return;
        }
        FinishClose(Slot);
    }

    [[nodiscard]] auto BindingLifetime::Activity::CloseAndDrain()
        -> Net::awaitable<Prism::Transmission::ControlResult>
    {
        const auto Value = Carrier_.load();
        if (!Value) co_return Prism::Transmission::ControlResult{};
        auto FirstFailure = Prism::Transmission::ControlResult{};
        const auto Cancelled = Value->Cancel();
        if (!Cancelled) FirstFailure = std::unexpected(Cancelled.error());
        const auto Closed = Value->Close();
        if (!Closed && FirstFailure) FirstFailure = std::unexpected(Closed.error());
        const auto Activity = Value->Activity();
        if (!Activity)
        {
            if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        Activity->Seal();
        const auto Drained = co_await Activity->Drain();
        if (!Drained && FirstFailure) FirstFailure = std::unexpected(Drained.error());
        const auto ActivityRetired = Activity->IsRetired();
        if (!ActivityRetired)
        {
            if (FirstFailure)
            {
                FirstFailure = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            (void)State_->Failure.TrySet(FirstFailure.error());
            co_return std::unexpected(FirstFailure.error());
        }

        if (auto Receipt = CloseReceipt_.load(std::memory_order_acquire))
        {
            Receipt->ConfirmExternalClose();
            const auto WrapperDrained = co_await Receipt->Drain();
            const auto WrapperActivity = Value->Activity();
            const bool WrapperRetired = WrapperActivity && WrapperActivity->IsRetired();
            if (!WrapperDrained && FirstFailure)
            {
                FirstFailure = std::unexpected(WrapperDrained.error());
            }
            if (!WrapperRetired)
            {
                if (FirstFailure)
                {
                    FirstFailure = std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
                (void)State_->Failure.TrySet(FirstFailure.error());
                co_return std::unexpected(FirstFailure.error());
            }
        }

        if (!FirstFailure)
        {
            (void)State_->Failure.TrySet(FirstFailure.error());
        }
        // 成功只表示实物与包装层真实退休；历史故障由 BindingLifetime::Drain 保留返回。
        co_return Prism::Transmission::ControlResult{};
    }

    auto BindingLifetime::Activity::PublishFatal(
        std::exception_ptr Error,
        const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
    {
        if (Context_ && Context_->Fatal) Context_->Fatal->Publish(std::move(Error));
        HoldFailure({Prism::Fault::Code::Blocked}, Slot);
    }

    auto BindingLifetime::Activity::FinishClose(
        const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
    {
        Retired_.store(true, std::memory_order_release);
        CloseInFlight_.store(false, std::memory_order_release);
        if (Slot) Slot->RetryPending.store(false, std::memory_order_release);
        Carrier_.store({});
        CloseReceipt_.store({});
        ReleaseFailedSlot(Slot);
    }

    auto BindingLifetime::Activity::ReleaseFailedSlot(
        const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void
    {
        if (!Slot || !Retired_.load() || IoActive_.load() != 0) return;
        Slot->PhysicallyRetired.store(true, std::memory_order_release);
        if (!Slot->Failed.exchange({})) return;
        if (auto Storage = Slot->Storage.lock()) Storage->Collect();
    }

    BindingLifetime::BindingLifetime(
        Net::any_io_executor Executor,
        Prism::Foundation::GenerationPin Generation)
        : State_(std::make_shared<CloseState>(std::move(Executor), std::move(Generation)))
    {
    }

    BindingLifetime::~BindingLifetime() noexcept
    {
        Close();
        for (const auto& Slot : *Entries_.load())
        {
            Slot->BindingOwned.store(false);
            if (auto Entry = Slot->Active.lock()) Entry->ReleaseBinding();
        }
    }

    [[nodiscard]] auto BindingLifetime::Enter(Prism::SharedTransmission Carrier)
        -> SharedActivity
    {
        if (!Carrier) return {};
        auto Slot = std::make_shared<ClosingSlot>();
        if (auto Storage = State_->Storage.lock(); Storage && Storage->IsSealed()) return {};
        if (!State_->Barrier.Enter()) return {};
        Prism::Lifecycle::DrainReservation Reservation(State_->Barrier);
        auto Entry = std::make_shared<Activity>(State_, std::move(Carrier));
        Reservation.Transfer();
        Slot->Active = Entry;
        Entry->Attach(Slot);
        for (;;)
        {
            auto Current = Entries_.load();
            auto Next = std::make_shared<Entries>();
            for (const auto& Value : *Current)
            {
                if (!Value->Active.expired() || Value->Failed.load()) Next->push_back(Value);
            }
            Next->push_back(Slot);
            if (Entries_.compare_exchange_weak(Current, Next)) break;
        }
        if (Closed_.load()) (void)Entry->RequestClose();
        return Entry;
    }

    auto BindingLifetime::Close() noexcept -> void
    {
        if (Closed_.exchange(true)) return;
        State_->Barrier.Seal();
        for (const auto& Slot : *Entries_.load())
        {
            if (auto Entry = Slot->Active.lock()) (void)Entry->RequestClose();
        }
    }

    [[nodiscard]] auto BindingLifetime::IsRetired() const noexcept -> bool
    {
        if (!Closed_.load(std::memory_order_acquire) || State_->Barrier.Active() != 0) return false;
        for (const auto& Slot : *Entries_.load(std::memory_order_acquire))
        {
            if (Slot->Failed.load(std::memory_order_acquire)) return false;
            if (Slot->Activated.load(std::memory_order_acquire) &&
                !Slot->PhysicallyRetired.load(std::memory_order_acquire)) return false;
        }
        return true;
    }

    auto BindingLifetime::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Close();
        if (State_->Context && !State_->Context->CanDispatch())
        {
            State_->Failure.TrySet({Prism::Fault::Code::Blocked});
            State_->Barrier.Block();
        }
        const auto Drained = co_await State_->Barrier.Drain();
        if (!Drained)
        {
            const auto Failure = State_->Failure.Load();
            if (IsRetired()) State_->Generation.reset();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::unexpected(Drained.error());
        }
        const auto Failure = State_->Failure.Load();
        State_->Generation.reset();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto BindingLifetime::ClosingSlot::RequestRetirement() noexcept -> void
    {
        if (auto Value = Failed.load()) Value->RequestRetirement();
    }

    BoundTransmission::IoReservation::IoReservation(
        BindingLifetime::SharedActivity Value)
        : Activity(std::move(Value))
    {
        Activity->BeginIo();
    }

    BoundTransmission::IoReservation::~IoReservation()
    {
        Activity->EndIo();
    }

    auto BoundTransmission::NotOpen() -> Prism::IoResult
    {
        return Prism::IoResult{
            0, Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::NotOpen))};
    }

    BoundTransmission::BoundTransmission(BindingLifetime::SharedActivity Activity)
        : Prism::Transmission(Activity->Executor()), Activity_(std::move(Activity))
    {
        Activity_->AttachCloseReceipt(CloseReceipt());
    }

    BoundTransmission::~BoundTransmission() noexcept
    {
        (void)Activity_->RequestClose();
    }

    [[nodiscard]] auto BoundTransmission::OnClose() -> ControlResult
    {
        (void)Owner();
        return Activity_->RequestClose();
    }

    [[nodiscard]] auto BoundTransmission::OnCancel() -> ControlResult
    {
        (void)Owner();
        auto Value = Activity_->Carrier();
        if (!Value) return {};
        return Value->Cancel();
    }

    [[nodiscard]] auto BoundTransmission::Owner() -> std::shared_ptr<BoundTransmission>
    {
        auto Value = std::static_pointer_cast<BoundTransmission>(Transmission::shared_from_this());
        return Value;
    }
} // namespace Prism::Protocols
