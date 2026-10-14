/**
 * @file Mailbox.hpp
 * @brief Preview worker 的固定容量 MPSC mailbox
 * @details 生产者通过原子 ticket 预留固定槽位，worker 作为唯一消费者按
 *          sequence 顺序回收。所有入口都是 try 操作，不使用 mutex、条件
 *          变量或无界容器。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>
#include <Preview/Runtime/WorkerDispatchResult.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <utility>

namespace Preview::Runtime::Detail
{

    class Mailbox final
    {
    public:
        using Command = WorkerDispatchCommand;

        struct Options final
        {
            std::size_t Capacity{64};
            Preview::GenerationId Generation{};
            std::shared_ptr<GenerationPublication> Publication;
        };

        Mailbox();

        explicit Mailbox(Options Value);

        ~Mailbox() noexcept;

        Mailbox(const Mailbox &) = delete;
        auto operator=(const Mailbox &) -> Mailbox & = delete;
        Mailbox(Mailbox &&) = delete;
        auto operator=(Mailbox &&) -> Mailbox & = delete;

        [[nodiscard]] auto Post(Preview::GenerationId Generation,
                                Command CommandValue) noexcept -> WorkerDispatchResult;

        [[nodiscard]] auto TryReceive(Command &CommandValue) noexcept -> bool;

        auto Close() noexcept -> void;

        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return Closed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Capacity() const noexcept -> std::size_t
        {
            return Capacity_;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t;

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            if (Publication_)
            {
                const auto Current = Publication_->Current();
                if (Current)
                {
                    return Current->Id();
                }
            }
            return Generation_;
        }

    private:
        struct Slot final
        {
            std::atomic<std::size_t> Sequence{0};
            Command Value{};
        };

        const std::size_t Capacity_;
        const Preview::GenerationId Generation_;
        std::shared_ptr<GenerationPublication> Publication_;
        std::unique_ptr<Slot[]> Slots_;
        std::atomic<std::size_t> Head_{0};
        std::atomic<std::size_t> Tail_{0};
        std::atomic<bool> Closed_{false};
    };

    inline Mailbox::Mailbox() : Mailbox(Options{})
    {
    }

    inline Mailbox::Mailbox(Options Value)
        : Capacity_(Value.Capacity == 0 ? 1 : Value.Capacity),
          Generation_(Value.Generation),
          Publication_(std::move(Value.Publication)),
          Slots_(std::make_unique<Slot[]>(Capacity_))
    {
    }

    inline Mailbox::~Mailbox() noexcept = default;

    inline auto Mailbox::Post(Preview::GenerationId Generation, Command CommandValue) noexcept
        -> WorkerDispatchResult
    {
        if (Closed_.load(std::memory_order_acquire))
        {
            return WorkerDispatchResult::Closed;
        }
        auto AcceptedGeneration = false;
        if (Publication_)
        {
            AcceptedGeneration = Publication_->Contains(Generation);
        }
        else
        {
            AcceptedGeneration = Generation == Generation_;
        }
        if (!AcceptedGeneration)
        {
            return WorkerDispatchResult::GenerationRejected;
        }

        auto Position = std::size_t{0};
        for (;;)
        {
            const auto Head = Head_.load(std::memory_order_acquire);
            Position = Tail_.load(std::memory_order_acquire);
            if (Position < Head)
            {
                Position = Head;
            }
            if (Position - Head >= Capacity_)
            {
                return WorkerDispatchResult::Full;
            }
            if (Tail_.compare_exchange_weak(Position, Position + 1,
                                             std::memory_order_acq_rel,
                                             std::memory_order_relaxed))
            {
                break;
            }
        }

        auto &SlotValue = Slots_[Position % Capacity_];
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

    inline auto Mailbox::TryReceive(Command &CommandValue) noexcept -> bool
    {
        const auto Position = Head_.load(std::memory_order_relaxed);
        auto &SlotValue = Slots_[Position % Capacity_];
        if (SlotValue.Sequence.load(std::memory_order_acquire) != Position + 1)
        {
            return false;
        }

        CommandValue = std::move(SlotValue.Value);
        SlotValue.Value = {};
        SlotValue.Sequence.store(Position + Capacity_, std::memory_order_release);
        Head_.store(Position + 1, std::memory_order_release);
        return true;
    }

    inline auto Mailbox::Close() noexcept -> void
    {
        Closed_.store(true, std::memory_order_release);
    }

    inline auto Mailbox::Size() const noexcept -> std::size_t
    {
        const auto Tail = Tail_.load(std::memory_order_acquire);
        const auto Head = Head_.load(std::memory_order_acquire);
        if (Tail >= Head)
        {
            return Tail - Head;
        }
        return 0;
    }

} // namespace Preview::Runtime::Detail
