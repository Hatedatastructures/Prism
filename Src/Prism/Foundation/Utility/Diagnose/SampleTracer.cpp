/**
 * @file SampleTracer.cpp
 * @brief 有界并发采样环实现。
 */
#include <Prism/Foundation/Utility/Diagnose/Observability.hpp>

#include <algorithm>

namespace Prism::Diagnose
{
    SampleTracer::SampleTracer(const std::uint64_t Ratio, const std::size_t RingSize)
        : Ratio_(1), RingSize_(NormalizeRingSize(RingSize)), Ring_(RingSize_)
    {
        if (Ratio < 1)
        {
            Ratio_ = 1;
        }
        else
        {
            Ratio_ = Ratio;
        }
    }

    auto SampleTracer::Sample(const std::uint64_t Value) -> void
    {
        const auto Seq = Counter_.fetch_add(1, std::memory_order_relaxed);
        if (Seq % Ratio_ != 0)
        {
            return;
        }
        const auto Ticket = ReserveTicket();
        if (!Ticket) { Dropped_.fetch_add(1, std::memory_order_relaxed); return; }
        auto& Slot = Ring_[*Ticket & (RingSize_ - 1)];
        if (Slot.Editing.test_and_set(std::memory_order_acquire))
        { Dropped_.fetch_add(1, std::memory_order_relaxed); return; }
        Slot.Sequence.store(0, std::memory_order_release);
        Slot.Value.store(Value, std::memory_order_release);
        Slot.Sequence.store(*Ticket + 1, std::memory_order_release);
        Slot.Editing.clear(std::memory_order_release);
        Sampled_.fetch_add(1, std::memory_order_relaxed);
    }

    auto SampleTracer::Drain(std::array<std::uint64_t, 8>& Output) const -> std::size_t
    {
        const auto Written = WriteIdx_.load(std::memory_order_relaxed);
        std::size_t N = 0;
        for (std::size_t I = 0; N < Output.size() && I < RingSize_ && I < Written; ++I)
        {
            const auto Expected = Written - I;
            const auto& Slot = Ring_[(Expected - 1) & (RingSize_ - 1)];
            const auto Before = Slot.Sequence.load(std::memory_order_acquire);
            if (Before != Expected) continue;
            const auto Value = Slot.Value.load(std::memory_order_acquire);
            if (Slot.Sequence.load(std::memory_order_acquire) != Before) continue;
            Output[N] = Value;
            ++N;
        }
        return N;
    }

    auto SampleTracer::Reset() noexcept -> void
    {
        Counter_.store(0U, std::memory_order_relaxed);
        Sampled_.store(0U, std::memory_order_relaxed);
        WriteIdx_.store(0U, std::memory_order_relaxed);
        Dropped_.store(0U, std::memory_order_relaxed);
        for (std::size_t Index = 0; Index < RingSize_; ++Index)
        {
            Ring_[Index].Sequence.store(0U, std::memory_order_relaxed);
            Ring_[Index].Value.store(0U, std::memory_order_relaxed);
            Ring_[Index].Editing.clear(std::memory_order_release);
        }
    }

    auto SampleTracer::ReserveTicket() noexcept -> std::optional<std::uint64_t>
    {
        auto Current = WriteIdx_.load(std::memory_order_relaxed);
        for (unsigned Attempt = 0; Attempt < 4 && Current != UINT64_MAX; ++Attempt)
            if (WriteIdx_.compare_exchange_strong(Current, Current + 1, std::memory_order_relaxed))
                return Current;
        return std::nullopt;
    }

    auto SampleTracer::NormalizeRingSize(const std::size_t Size) noexcept -> std::size_t
    {
        if (Size == 0 || (Size & (Size - 1)) != 0)
        {
            return DefaultRingSize;
        }
        return (std::min)(Size, MaxRingSize);
    }
}
