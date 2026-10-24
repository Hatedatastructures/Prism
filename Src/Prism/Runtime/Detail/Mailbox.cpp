/** @file Mailbox.cpp @brief 固定容量 MPSC mailbox 的顺序提交与回收。 */
#include <Prism/Runtime/Detail/Mailbox.hpp>

#include <utility>

namespace Prism::Runtime::Detail
{
    Mailbox::Mailbox() : Mailbox(Options{})
    {
    }

    Mailbox::Mailbox(Options Value)
        : Capacity_(Value.Capacity == 0 ? 1 : Value.Capacity),
          Generation_(Value.Generation), Publication_(std::move(Value.Publication)),
          Slots_(std::make_unique<Slot[]>(Capacity_))
    {
    }

    Mailbox::~Mailbox() noexcept = default;

    auto Mailbox::Post(const Prism::GenerationId Generation, Command CommandValue) noexcept
        -> WorkerDispatchResult
    {
        if (Closed_.load(std::memory_order_acquire)) return WorkerDispatchResult::Closed;
        const auto AcceptedGeneration = Publication_
            ? Publication_->Contains(Generation)
            : Generation == Generation_;
        if (!AcceptedGeneration) return WorkerDispatchResult::GenerationRejected;
        auto Position = std::size_t{0};
        for (;;)
        {
            const auto Head = Head_.load(std::memory_order_acquire);
            Position = Tail_.load(std::memory_order_acquire);
            if (Position < Head) Position = Head;
            if (Position - Head >= Capacity_) return WorkerDispatchResult::Full;
            if (Tail_.compare_exchange_weak(Position, Position + 1,
                std::memory_order_acq_rel, std::memory_order_relaxed)) break;
        }
        auto& SlotValue = Slots_[Position % Capacity_];
        if (Closed_.load(std::memory_order_acquire))
        {
            SlotValue.Value = {};
            SlotValue.Sequence.store(Position + 1, std::memory_order_release);
            return WorkerDispatchResult::Closed;
        }
        SlotValue.Value = std::move(CommandValue);
        SlotValue.Sequence.store(Position + 1, std::memory_order_release);
        return WorkerDispatchResult::Accepted;
    }

    auto Mailbox::TryReceive(Command& CommandValue) noexcept -> bool
    {
        const auto Position = Head_.load(std::memory_order_relaxed);
        auto& SlotValue = Slots_[Position % Capacity_];
        if (SlotValue.Sequence.load(std::memory_order_acquire) != Position + 1) return false;
        CommandValue = std::move(SlotValue.Value);
        SlotValue.Value = {};
        SlotValue.Sequence.store(Position + Capacity_, std::memory_order_release);
        Head_.store(Position + 1, std::memory_order_release);
        return true;
    }

    auto Mailbox::Close() noexcept -> void
    {
        Closed_.store(true, std::memory_order_release);
    }

    auto Mailbox::IsClosed() const noexcept -> bool
    {
        return Closed_.load(std::memory_order_acquire);
    }

    auto Mailbox::Capacity() const noexcept -> std::size_t
    {
        return Capacity_;
    }

    auto Mailbox::Size() const noexcept -> std::size_t
    {
        const auto Tail = Tail_.load(std::memory_order_acquire);
        const auto Head = Head_.load(std::memory_order_acquire);
        return Tail >= Head ? Tail - Head : 0;
    }

    auto Mailbox::Generation() const noexcept -> Prism::GenerationId
    {
        if (Publication_)
            if (const auto Current = Publication_->Current()) return Current->Id();
        return Generation_;
    }
}
