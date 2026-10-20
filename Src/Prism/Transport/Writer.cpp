/** @file Writer.cpp @brief 按序写入状态机与异步归还实现。 */
#include <Prism/Transport/Writer.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Prism::Transport
{
    Writer::CloseCompletion::CloseCompletion(std::shared_ptr<State> Value)
        : Owner(std::move(Value))
    {
    }

    Writer::CloseCompletion::CloseCompletion(CloseCompletion&& Other) noexcept
        : Owner(std::move(Other.Owner)), Returned(Other.Returned)
    {
    }

    Writer::CloseCompletion::~CloseCompletion()
    {
        if (!Owner) return;
        if (!Returned) { Owner->Fail(); return; }
        if (!Owner->CloseReturned.try_send(boost::system::error_code{})) Owner->Fail();
    }

    auto Writer::CloseCompletion::get_executor() const noexcept -> executor_type
    {
        return Owner->Reclaimer->Executor();
    }

    auto Writer::CloseCompletion::get_allocator() const noexcept -> allocator_type
    {
        return {};
    }

    auto Writer::CloseCompletion::operator()(std::exception_ptr Error, ControlResult Result) -> void
    {
        Returned = true;
        if (Error) { Owner->Fail(); Owner->Fatal->Publish(std::move(Error)); return; }
        if (!Result) Owner->Fail(Result.error());
    }

    Writer::CloseRetirement::CloseRetirement(std::shared_ptr<State> Value)
        : Owner(std::move(Value))
    {
    }

    Writer::CloseRetirement::CloseRetirement(CloseRetirement&& Other) noexcept
        : Owner(std::move(Other.Owner)), Returned(Other.Returned)
    {
    }

    Writer::CloseRetirement::~CloseRetirement()
    {
        if (Owner && !Returned) Owner->Fail();
    }

    auto Writer::CloseRetirement::operator()(boost::system::error_code Error) -> void
    {
        Returned = true;
        if (Error) { Owner->Fail(Fault::FromNative(static_cast<std::error_code>(Error))); return; }
        if (Owner->Blocked.load(std::memory_order_acquire)) return;
        Owner->CloseConfirmed.store(true, std::memory_order_release);
        if (Owner->CloseEntered.exchange(false)) Owner->Barrier.Leave();
        Owner->Storage->Collect();
    }

    Writer::Release::Release(std::shared_ptr<State> Value, std::size_t SlotIndex)
        : Owner(std::move(Value)), Index(SlotIndex)
    {
    }

    Writer::Release::Release(Release&& Other) noexcept
        : Owner(std::move(Other.Owner)), Index(Other.Index)
    {
    }

    Writer::Release::~Release()
    {
        if (Owner && !Returned) Owner->Fail();
    }

    auto Writer::Release::operator()(boost::system::error_code Error) -> void
    {
        if (Error) { Owner->Fail(Fault::FromNative(static_cast<std::error_code>(Error))); Returned = true; return; }
        auto& Entry = Owner->Slots[Index];
        if (Entry.NativeActive.load())
        { Owner->Fail(); Returned = true; return; }
        Entry.Chunk.reset(); Entry.Input = {}; Entry.Handler = nullptr;
        Entry.Ready.store(false);
        if (Entry.Entered) { Entry.Entered = false; Owner->Barrier.Leave(); }
        Entry.Used.store(false, std::memory_order_release); Returned = true;
        Owner->Storage->Collect();
    }

    Writer::CompletionDelivery::CompletionDelivery(
        std::shared_ptr<State> Owner, std::size_t Index, Completion Handler)
        : Detail::AssociatedCompletion<Completion>(std::move(Handler)),
          Owner_(std::move(Owner)), Index_(Index)
    {
    }

    Writer::CompletionDelivery::CompletionDelivery(CompletionDelivery&& Other) noexcept
        : Detail::AssociatedCompletion<Completion>(std::move(Other.Handler_)),
          Owner_(std::move(Other.Owner_)), Index_(Other.Index_), Returned_(Other.Returned_)
    {
    }

    Writer::CompletionDelivery::~CompletionDelivery()
    {
        if (!Owner_) return;
        if (!Returned_) { Owner_->Slots[Index_].Handler = std::move(Handler_); Owner_->Fail(); return; }
        if (!Owner_->Slots[Index_].Returned->try_send(boost::system::error_code{})) Owner_->Fail();
    }

    auto Writer::CompletionDelivery::operator()(IoResult Result) -> void
    {
        std::move(Handler_)(Result);
        Returned_ = true;
    }

    Writer::Wake::Wake(std::shared_ptr<State> Value, WakeKind Action)
        : Owner(std::move(Value)), Kind(Action)
    {
    }

    Writer::Wake::Wake(Wake&& Other) noexcept
        : Owner(std::move(Other.Owner)), Kind(Other.Kind)
    {
    }

    Writer::Wake::~Wake()
    {
        if (!Owner) return;
        if (!Returned) { Owner->Fail(); return; }
        if (Kind == WakeKind::StopCancel) Owner->Barrier.Leave();
        Owner->Tasks.Leave();
        Owner->Storage->Collect();
    }

    auto Writer::Wake::operator()() -> void
    {
        if (Kind != WakeKind::Pump) Returned = Owner->Stop();
        else { Owner->Pump(); Returned = true; }
    }

    auto Writer::CancelRequest::operator()(Net::cancellation_type Type) const -> void
    {
        if (Type == Net::cancellation_type::none) return;
        if (auto Value = Owner.lock())
        {
            if (!Value->Tasks.Enter()) return;
            const auto Result = Value->Reclaimer->Post(CancelAction(Value, Index, Ticket));
            if (!Result) Value->Fail(Result.error());
        }
    }

    Writer::CancelAction::CancelAction(std::shared_ptr<State> Value, std::size_t Slot, std::uint64_t Number)
        : Owner(std::move(Value)), Index(Slot), Ticket(Number)
    {
    }

    Writer::CancelAction::CancelAction(CancelAction&& Other) noexcept
        : Owner(std::move(Other.Owner)), Index(Other.Index), Ticket(Other.Ticket)
    {
    }

    Writer::CancelAction::~CancelAction()
    {
        if (!Owner) return;
        if (!Returned) { Owner->Fail(); return; }
        Owner->Tasks.Leave();
        Owner->Storage->Collect();
    }

    auto Writer::CancelAction::operator()() -> void
    {
        Owner->CancelSlot(Index, Ticket);
        Returned = true;
    }

    Writer::PartialCompletion::PartialCompletion(std::shared_ptr<State> Owner, std::size_t Index)
        : Owner_(std::move(Owner)), Index_(Index)
    {
    }

    Writer::PartialCompletion::PartialCompletion(PartialCompletion&& Other) noexcept
        : Owner_(std::move(Other.Owner_)), Index_(Other.Index_), Returned_(Other.Returned_)
    {
    }

    Writer::PartialCompletion::~PartialCompletion()
    {
        if (!Owner_) return;
        Owner_->Slots[Index_].NativeActive.store(false);
        if (!Returned_) Owner_->Fail();
    }

    auto Writer::PartialCompletion::get_executor() const noexcept -> executor_type
    {
        return Owner_->Reclaimer->Executor();
    }

    auto Writer::PartialCompletion::get_allocator() const noexcept -> allocator_type
    {
        return Owner_->CleanupMemory;
    }

    auto Writer::PartialCompletion::get_cancellation_slot() const noexcept -> cancellation_slot_type
    {
        return Owner_->Slots[Index_].Cancel.slot();
    }

    auto Writer::PartialCompletion::operator()(IoResult Result) -> void
    {
        Owner_->Partial(Index_, Result);
        Returned_ = true;
    }

    Writer::State::State(std::shared_ptr<Memory::BytePool> Bytes, std::shared_ptr<WriteDriver> Port)
        : Bytes(std::move(Bytes)), Driver(std::move(Port)),
          Context(Prism::Executor::ContextOwner::Find(Driver->Executor())),
          Storage(Prism::Executor::ContextOwner::Storage(Driver->Executor())),
          Fatal(Prism::Executor::FatalState::For(Driver->Executor())),
          Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(Net::make_strand(Driver->Executor()))),
          Barrier(Reclaimer), Tasks(Reclaimer), CloseReturned(Reclaimer->Executor(), 1)
    {
        for (auto& Entry : Slots)
            Entry.Returned = std::make_unique<ReturnSignal>(Reclaimer->Executor(), 1);
    }

    auto Writer::State::Fail(Fault::Failure Error) noexcept -> void
    {
        if (RetainedFailure.TrySet(Error))
        {
            Blocked.store(true, std::memory_order_release);
            Barrier.Block();
            Tasks.Block();
        }
        Storage->Retain(shared_from_this());
    }

    auto Writer::State::PostWake(WakeKind Kind) -> ControlResult
    {
        if (!Tasks.Enter()) return std::unexpected(RetainedFailure.Load());
        auto Result = Reclaimer->Post(Wake(shared_from_this(), Kind));
        if (!Result) Fail(Result.error());
        return Result;
    }

    auto Writer::State::Notify() -> void
    {
        (void)PostWake(WakeKind::Pump);
    }

    auto Writer::State::Submit(std::span<const std::byte> Input, Completion Handler, bool Shutdown) -> void
    {
        std::size_t Index = Capacity;
        if (!Shutdown)
        {
            if (Sealed.load()) { Prism::Transmission::PostResult(Reclaimer->Executor(), std::move(Handler), {0, {Fault::Code::Canceled}}); return; }
            for (Index = 0; Index < Capacity; ++Index) if (!Slots[Index].Used.exchange(true)) break;
            if (Index == Capacity) { Prism::Transmission::PostResult(Reclaimer->Executor(), std::move(Handler), {0, {Fault::Code::ResourceUnavailable}}); return; }
        }
        else
        {
            if (Slots[Index].Used.exchange(true)) { Prism::Transmission::PostResult(Reclaimer->Executor(), std::move(Handler), {0, {Fault::Code::WouldBlock}}); return; }
            Sealed.store(true);
        }
        auto& Entry = Slots[Index];
        Entry.Handler = std::move(Handler);
        Entry.Input = Input;
        Entry.Ticket.store(NextTicket.fetch_add(1));
        Entry.Total = 0; Entry.Offset = 0; Entry.Canceled = false; Entry.Entered = false; Entry.Completed.store(false);
        if (!Barrier.Enter())
        {
            auto Refused = std::move(Entry.Handler);
            Entry.Input = {};
            Entry.Used.store(false, std::memory_order_release);
            Prism::Transmission::PostResult(Reclaimer->Executor(), std::move(Refused), {0, {Fault::Code::Canceled}});
            return;
        }
        Entry.Entered = true;
        Entry.Returned->async_receive(Net::bind_allocator(CleanupMemory,
            Net::bind_executor(Reclaimer->Executor(), Release(shared_from_this(), Index))));
        if (!Shutdown && Sealed.load()) { Complete(Index, {0, {Fault::Code::Canceled}}); return; }
        if (!Input.empty())
        {
            if (!Bytes || Bytes->BlockSize() != ChunkSize)
            { Complete(Index, {0, {Fault::Code::InvalidArgument}}); return; }
            auto Lease = Bytes->TryAcquire((std::min)(Input.size(), ChunkSize));
            if (!Lease) { Complete(Index, {0, Lease.error()}); return; }
            Entry.Chunk.emplace(std::move(*Lease));
            std::memcpy(Entry.Chunk->WritableBytes().data(), Input.data(), Entry.Chunk->Size());
        }
        auto Cancel = Net::get_associated_cancellation_slot(Entry.Handler);
        if (Cancel.is_connected()) Cancel.assign(CancelRequest{shared_from_this(), Index, Entry.Ticket.load()});
        Entry.Ready.store(true, std::memory_order_release);
        Notify();
    }

    auto Writer::State::Pump() -> void
    {
        if (Active) return;
        if (Closing.load() && !CloseIssued)
        {
            for (const auto& Entry : Slots) if (Entry.NativeActive.load()) return;
            const auto Result = Driver->Close();
            if (!Result) { Fail(Result.error()); return; }
            CloseIssued = true;
            BeginCloseDrain();
        }
        std::optional<std::size_t> Selected;
        auto Ticket = (std::numeric_limits<std::uint64_t>::max)();
        for (std::size_t Index = 0; Index <= Capacity; ++Index)
        {
            const auto& Entry = Slots[Index];
            if (!Entry.Used.load() || Entry.Completed.load()) continue;
            if (!Entry.Ready.load()) return;
            if (Entry.Ticket.load() < Ticket) { Ticket = Entry.Ticket.load(); Selected = Index; }
        }
        if (!Selected) return;
        const auto Index = *Selected;
        auto& Entry = Slots[Index];
        if (Terminal.Failed()) { Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
        if (Entry.Canceled) { Complete(Index, {Entry.Total, {Fault::Code::Canceled}}); Notify(); return; }
        Active = Index;
        Entry.NativeActive.store(true);
        if (Index == Capacity) { Driver->WriteShutdown(PartialCompletion(shared_from_this(), Index)); return; }
        if (Entry.Input.empty()) { Entry.NativeActive.store(false); Active.reset(); Complete(Index, {}); Notify(); return; }
        Driver->WritePartial(Entry.Chunk->Bytes().subspan(Entry.Offset), PartialCompletion(shared_from_this(), Index));
    }

    auto Writer::State::BeginCloseDrain() -> void
    {
        auto Activity = Driver->Activity();
        if (!Activity) { Fail({Fault::Code::InvalidArgument}); return; }
        CloseReturned.async_receive(Net::bind_allocator(CleanupMemory,
            Net::bind_executor(Reclaimer->Executor(), CloseRetirement(shared_from_this()))));
        Net::co_spawn(Reclaimer->Executor(), AwaitClose(std::move(Activity)), CloseCompletion(shared_from_this()));
    }

    auto Writer::State::AwaitClose(std::shared_ptr<Contract::CarrierActivity> Activity)
        -> Net::awaitable<ControlResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        const auto Result = co_await Activity->Drain();
        if (!Result) co_return std::unexpected(Result.error());
        if (!Activity->IsRetired())
            co_return std::unexpected(Fault::Failure{Fault::Code::Blocked});
        co_return ControlResult{};
    }

    auto Writer::State::Partial(std::size_t Index, IoResult Result) -> void
    {
        auto& Entry = Slots[Index];
        if (Index != Capacity)
        {
            const auto Remaining = Entry.Chunk->Size() - Entry.Offset;
            if (Result.Bytes > Remaining) { Result.Bytes = 0; Result.Failure.Code = Fault::Code::InvalidArgument; }
            Entry.Total += Result.Bytes;
            Entry.Offset += Result.Bytes;
        }
        if (Result.Failure.Failed())
        { if (Terminal.Succeeded() || !Terminal.Native) Terminal = Result.Failure; Sealed.store(true); }
        if (Entry.Canceled && !Terminal.Failed()) { Terminal = {Fault::Code::Canceled}; Sealed.store(true); }
        if (Terminal.Failed() || Index == Capacity || Entry.Total == Entry.Input.size())
        { Active.reset(); Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
        if (Result.Bytes == 0)
        { Terminal = {Fault::Code::WouldBlock}; Active.reset(); Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
        if (Entry.Offset == Entry.Chunk->Size())
        {
            const auto Size = (std::min)(Entry.Input.size() - Entry.Total, ChunkSize);
            const auto Resized = Entry.Chunk->Resize(Size);
            if (!Resized) { Terminal = Resized.error(); Active.reset(); Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
            std::memcpy(Entry.Chunk->WritableBytes().data(), Entry.Input.data() + Entry.Total, Size);
            Entry.Offset = 0;
        }
        Active.reset();
        Notify();
    }

    auto Writer::State::Complete(std::size_t Index, IoResult Result) -> void
    {
        auto& Entry = Slots[Index];
        if (Entry.Completed.exchange(true)) return;
        auto Cancellation = Net::get_associated_cancellation_slot(Entry.Handler);
        if (Cancellation.is_connected()) Cancellation.clear();
        Completion Handler(CompletionDelivery(shared_from_this(), Index, std::move(Entry.Handler)));
        Prism::Transmission::PostResult(Reclaimer->Executor(), std::move(Handler), Result);
    }

    auto Writer::State::CancelSlot(std::size_t Index, std::uint64_t Ticket) -> void
    {
        auto& Entry = Slots[Index];
        if (!Entry.Used.load() || Entry.Ticket.load() != Ticket || Entry.Completed.load()) return;
        Entry.Canceled = true;
        if (Active && *Active == Index) Entry.Cancel.emit(Net::cancellation_type::all);
        Notify();
    }

    auto Writer::State::RequestCancel() -> ControlResult
    {
        Sealed.store(true);
        if (!Barrier.Enter())
        { if (Blocked.load()) return std::unexpected(RetainedFailure.Load()); return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
        return PostWake(WakeKind::StopCancel);
    }

    auto Writer::State::RequestClose() -> ControlResult
    {
        Sealed.store(true);
        if (Closing.exchange(true)) { if (Blocked.load()) return std::unexpected(RetainedFailure.Load()); return {}; }
        if (!Barrier.Enter()) { Fail(); return std::unexpected(RetainedFailure.Load()); }
        CloseEntered.store(true);
        return PostWake(WakeKind::StopClose);
    }

    auto Writer::State::RequestRetirement() -> void
    {
        if (!Closing.load()) { (void)RequestClose(); return; }
        if (!CloseIssued) (void)PostWake(WakeKind::StopClose);
    }

    auto Writer::State::Seal() noexcept -> void
    {
        Sealed.store(true);
        Barrier.Seal();
    }

    auto Writer::State::Executor() const -> Net::any_io_executor
    {
        return Reclaimer->Executor();
    }

    auto Writer::State::Drain() -> Net::awaitable<ControlResult>
    {
        Seal();
        return DrainState(shared_from_this());
    }

    auto Writer::State::DrainState(std::shared_ptr<State> Owner) -> Net::awaitable<ControlResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        auto Result = co_await Owner->Barrier.Drain();
        if (Result) Result = co_await Owner->Tasks.Drain();
        if (!Result)
        {
            if (Owner->Blocked.load(std::memory_order_acquire))
                co_return std::unexpected(Owner->RetainedFailure.Load());
            co_return std::unexpected(Result.error());
        }
        co_return ControlResult{};
    }

    auto Writer::State::Stop() -> bool
    {
        if (Terminal.Succeeded()) Terminal = {Fault::Code::Canceled};
        if (Active) Slots[*Active].Cancel.emit(Net::cancellation_type::all);
        const auto Canceled = Driver->Cancel();
        if (!Canceled) { Fail(Canceled.error()); return false; }
        Notify();
        return true;
    }

    auto Writer::State::IsRetired() const noexcept -> bool
    {
        return CloseConfirmed.load() && Barrier.Active() == 0 && Tasks.Active() == 0 && !Blocked.load();
    }

    auto Writer::State::IsDispatchUnavailable() const noexcept -> bool
    {
        return Blocked.load() &&
            (RetainedFailure.Load().Code == Fault::Code::Blocked || !Reclaimer->CanDispatch());
    }

    Writer::Writer(std::shared_ptr<Memory::BytePool> Bytes, std::shared_ptr<WriteDriver> Driver)
        : State_(std::make_shared<State>(std::move(Bytes), std::move(Driver)))
    {
    }

    auto Writer::Write(std::span<const std::byte> Input, Completion Handler) -> void
    {
        State_->Submit(Input, std::move(Handler), false);
    }

    auto Writer::WriteShutdown(Completion Handler) -> void
    {
        State_->Submit({}, std::move(Handler), true);
    }

    auto Writer::Close() -> ControlResult
    {
        State_->Storage->Retain(State_);
        return State_->RequestClose();
    }

    auto Writer::Cancel() -> ControlResult
    {
        return State_->RequestCancel();
    }

    auto Writer::Drain() -> Net::awaitable<ControlResult>
    {
        return State_->Drain();
    }

    auto Writer::Activity() const -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return State_;
    }

    auto Writer::IsIdle() const noexcept -> bool
    {
        return State_->Barrier.Active() == 0 && State_->Tasks.Active() == 0 && !State_->Barrier.IsBlocked();
    }
} // namespace Prism::Transport
