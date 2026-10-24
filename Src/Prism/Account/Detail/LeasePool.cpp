/** @file LeasePool.cpp
 * @brief 账户 root lease 槽池的获取、归还与关闭实现。
 */
#include <Prism/Account/Detail/LeasePool.hpp>

#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <stdexcept>

namespace Prism::Account::Detail
{
        auto RootLeaseSlot::Close() noexcept -> void
        {
            const auto Before = Children.fetch_or(ClosedBit, std::memory_order_acq_rel);
            if ((Before & ~ClosedBit) == 0U) { ReleaseConnection(); }
        }

        auto RootLeaseSlot::TryAttachChild() noexcept -> std::expected<void, Fault::Failure>
        {
            auto State = Children.load(std::memory_order_acquire);
            for (;;)
            {
                if ((State & ClosedBit) != 0U) { return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
                if (State == ClosedBit - 1U) { return std::unexpected(MakeFailure(FailureReason::RootSlots)); }
                if (Children.compare_exchange_weak(State, State + 1U, std::memory_order_acq_rel,
                    std::memory_order_acquire)) { return {}; }
            }
        }

        auto RootLeaseSlot::DetachChild() noexcept -> void
        {
            const auto Before = Children.fetch_sub(1U, std::memory_order_acq_rel);
            if (Before == ClosedBit + 1U) { ReleaseConnection(); }
        }

        auto RootLeaseSlot::Open() const noexcept -> bool { return (Children.load(std::memory_order_acquire) & ClosedBit) == 0U; }

        auto RootLeaseSlot::ReleaseConnection() noexcept -> void
        {
            if (Connected.exchange(false, std::memory_order_acq_rel)) { Binding->Runtime()->ReleaseConnection(); }
        }

        LeasePool::LeasePool(const std::size_t Capacity) : Capacity_(CheckedCapacity(Capacity)), WordCount_((Capacity_ + 63U) / 64U),
            Slots_(std::make_unique<RootLeaseSlot[]>(Capacity_)), Words_(std::make_unique<std::atomic<std::uint64_t>[]>(WordCount_)) {}

        auto LeasePool::TryAcquire() noexcept -> std::expected<RootLeaseSlot*, Fault::Failure>
        {
            const auto Start = Hint_.fetch_add(1U, std::memory_order_relaxed) % WordCount_;
            for (std::size_t Offset = 0U; Offset < WordCount_; ++Offset)
            {
                const auto Word = (Start + Offset) % WordCount_;
                auto Used = Words_[Word].load(std::memory_order_relaxed);
                for (unsigned Attempt = 0U; Attempt < 4U && Used != UINT64_MAX; ++Attempt)
                {
                    const auto Bit = std::countr_zero(~Used);
                    const auto Index = Word * 64U + Bit;
                    if (Index >= Capacity_) { break; }
                    if (Words_[Word].compare_exchange_strong(Used, Used | (std::uint64_t{1U} << Bit),
                        std::memory_order_acquire, std::memory_order_relaxed))
                    {
                        auto* Result = &Slots_[Index];
                        Result->References.store(1U, std::memory_order_relaxed);
                        Result->Children.store(0U, std::memory_order_relaxed);
                        Result->Connected.store(false, std::memory_order_relaxed);
                        Result->Admission = {};
                        return Result;
                    }
                }
            }
            return std::unexpected(MakeFailure(FailureReason::RootSlots));
        }

        auto LeasePool::Hold(RootLeaseSlot* Slot) noexcept -> void { Slot->References.fetch_add(1U, std::memory_order_relaxed); }

        auto LeasePool::Release(RootLeaseSlot* Slot) noexcept -> void
        {
            if (!Slot || Slot->References.fetch_sub(1U, std::memory_order_acq_rel) != 1U) { return; }
            Slot->Close();
            Slot->Admission = {};
            Slot->Binding.reset();
            const auto Index = static_cast<std::size_t>(Slot - Slots_.get());
            Words_[Index / 64U].fetch_and(~(std::uint64_t{1U} << (Index % 64U)), std::memory_order_release);
        }

        auto LeasePool::CheckedCapacity(const std::size_t Capacity) -> std::size_t
        {
            if (Capacity == 0U || Capacity > 65536U) { throw std::invalid_argument("invalid account root lease capacity"); }
            return Capacity;
        }
}
