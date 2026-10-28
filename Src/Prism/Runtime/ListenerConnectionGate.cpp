/** @file ListenerConnectionGate.cpp @brief TCP 监听器配额与排空预留实现。 */
#include <Prism/Runtime/ListenerConnectionGate.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>

#include <system_error>
#include <utility>

namespace Prism::Runtime::Detail
{
    ListenerConnectionGate::Quota::Quota(
        const std::size_t LimitValue,
        Net::any_io_executor Executor)
        : Limit(LimitValue),
          Drain(std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor)))
    {
    }

    auto ListenerConnectionGate::TryAcquire(const SharedQuota& Value) noexcept -> bool
    {
        if (!Value) return false;
        if (Value->Limit == 0) return Value->Drain.Enter();
        auto Current = Value->Active.load(std::memory_order_relaxed);
        while (Current < Value->Limit &&
               !Value->Active.compare_exchange_weak(Current, Current + 1U,
                   std::memory_order_acquire, std::memory_order_relaxed))
        {
        }
        if (Current >= Value->Limit) return false;
        if (Value->Drain.Enter()) return true;
        Value->Active.fetch_sub(1U, std::memory_order_release);
        return false;
    }

    auto ListenerConnectionGate::ReturnQuota(const SharedQuota& Value) noexcept -> void
    {
        if (!Value) return;
        if (Value->Limit != 0)
        {
            auto Current = Value->Active.load(std::memory_order_acquire);
            while (Current != 0 &&
                   !Value->Active.compare_exchange_weak(Current, Current - 1U,
                       std::memory_order_acq_rel, std::memory_order_acquire))
            {
            }
        }
        Value->Drain.Leave();
    }

    ListenerConnectionGate::Reservation::Reservation(
        SharedQuota Value,
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage,
        std::shared_ptr<Prism::Runtime::Worker::AdmissionReceipt> WorkerReceipt) noexcept
        : Quota_(std::move(Value)),
          Storage_(std::move(Storage)),
          WorkerReceipt_(std::move(WorkerReceipt))
    {
    }

    ListenerConnectionGate::Reservation::~Reservation() noexcept
    {
        if (!RetainOnDrop_.load(std::memory_order_acquire))
        {
            Release();
        }
    }

    ListenerConnectionGate::Reservation::Reservation(Reservation&& Other) noexcept
        : Quota_(std::move(Other.Quota_)),
          Transport_(std::move(Other.Transport_)),
          Storage_(std::move(Other.Storage_)),
          WorkerReceipt_(std::move(Other.WorkerReceipt_)),
          Returned_(Other.Returned_.load(std::memory_order_acquire)),
          RetainOnDrop_(Other.RetainOnDrop_.load(std::memory_order_acquire))
    {
        Other.Returned_.store(true, std::memory_order_release);
        Other.RetainOnDrop_.store(true, std::memory_order_release);
    }

    auto ListenerConnectionGate::Reservation::RetainOnDrop() noexcept -> void
    {
        RetainOnDrop_.store(true, std::memory_order_release);
    }

    auto ListenerConnectionGate::Reservation::ReleaseTransport() noexcept -> void
    {
        Transport_.reset();
    }

    auto ListenerConnectionGate::Reservation::AdoptTransport(
        Prism::SharedTransmission Value) noexcept -> void
    {
        if (!Transport_) Transport_ = std::move(Value);
    }

    auto ListenerConnectionGate::Reservation::Release() noexcept -> void
    {
        if (Returned_.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        ListenerConnectionGate::ReturnQuota(Quota_);
        if (WorkerReceipt_)
        {
            WorkerReceipt_->Release();
            WorkerReceipt_.reset();
        }
    }

    auto ListenerConnectionGate::Reservation::BlockDrain() noexcept -> void
    {
        if (Quota_) Quota_->Drain.Block();
        if (WorkerReceipt_) WorkerReceipt_->Block();
    }

    auto ListenerConnectionGate::Reservation::RequestRetirement() noexcept -> void
    {
        if (Retired_.load(std::memory_order_acquire)) return;
        if (Blocked_.exchange(false, std::memory_order_acq_rel))
            Started_.store(false, std::memory_order_release);
        if (Started_.exchange(true, std::memory_order_acq_rel)) return;
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
            Block(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            Block({Prism::Fault::Code::Blocked});
        }
    }

    auto ListenerConnectionGate::Reservation::IsRetired() const noexcept -> bool
    {
        return Retired_.load(std::memory_order_acquire);
    }

    auto ListenerConnectionGate::Reservation::IsDispatchUnavailable() const noexcept -> bool
    {
        return Blocked_.load(std::memory_order_acquire);
    }

    ListenerConnectionGate::Reservation::DispatchCompletion::DispatchCompletion(
        std::shared_ptr<Reservation> Value,
        const std::uint64_t ValueGeneration) noexcept
        : Owner(std::move(Value)), Generation(ValueGeneration)
    {
    }

    ListenerConnectionGate::Reservation::DispatchCompletion::DispatchCompletion(
        DispatchCompletion&& Other) noexcept
        : Owner(std::move(Other.Owner)),
          Generation(Other.Generation),
          Error(std::move(Other.Error)),
          Invoked(Other.Invoked)
    {
    }

    ListenerConnectionGate::Reservation::DispatchCompletion::~DispatchCompletion() noexcept
    {
        if (!Owner) return;
        if (!Invoked) Owner->OnDispatchDropped(Generation);
        else Owner->OnDispatchCompleted(Generation, Error);
    }

    auto ListenerConnectionGate::Reservation::DispatchCompletion::operator()(
        std::exception_ptr Error) noexcept -> void
    {
        Invoked = true;
        this->Error = std::move(Error);
    }

    auto ListenerConnectionGate::Reservation::Run(std::shared_ptr<Reservation> Owner)
        -> Net::awaitable<void>
    {
        try
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Canceled = Owner->Transport_->Cancel();
            const auto Closed = Owner->Transport_->Close();
            if (!Canceled)
            {
                Owner->Block(Canceled.error());
                co_return;
            }
            if (!Closed)
            {
                Owner->Block(Closed.error());
                co_return;
            }
            const auto Activity = Owner->Transport_->Activity();
            if (!Activity)
            {
                Owner->Block({Prism::Fault::Code::InvalidArgument});
                co_return;
            }
            const auto Drained = co_await Activity->Drain();
            if (!Drained)
            {
                Owner->Block(Drained.error());
                co_return;
            }
            Owner->Completed_.store(true, std::memory_order_release);
        }
        catch (const std::system_error& Error)
        {
            Owner->Block(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            Owner->Block({Prism::Fault::Code::IoError});
        }
    }

    auto ListenerConnectionGate::Reservation::Block(Prism::Fault::Failure Error) noexcept -> void
    {
        BlockDrain();
        Failure_.Record(Error);
        Completed_.store(false, std::memory_order_release);
        Blocked_.store(true, std::memory_order_release);
        Started_.store(false, std::memory_order_release);
    }

    auto ListenerConnectionGate::Reservation::OnDispatchDropped(
        const std::uint64_t Generation) noexcept -> void
    {
        if (Generation == DispatchGeneration_.load(std::memory_order_acquire) &&
            !Retired_.load(std::memory_order_acquire))
            Block({Prism::Fault::Code::Blocked});
    }

    auto ListenerConnectionGate::Reservation::OnDispatchCompleted(
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
        if (!Completed_.load(std::memory_order_acquire)) return;
        Transport_.reset();
        Retired_.store(true, std::memory_order_release);
        Release();
        Storage_->Collect();
    }
}
