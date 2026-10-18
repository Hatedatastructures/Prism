/** @file LeasePool.hpp
 * @brief process 共享根账户 lease 槽，准入和归还无分配。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Account/Binding.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <array>
#include <atomic>
#include <bit>
#include <memory>
#include <expected>
#include <limits>
#include <stdexcept>

namespace Prism::Account::Detail
{
    /** @brief 元数据引用与真实 child 额度分别计数，root封止不能被旧 admission view 绕过。 */
    struct RootLeaseSlot final
    {
        static constexpr std::uint64_t ClosedBit = std::uint64_t{1U} << 63U;
        std::shared_ptr<const AccountBinding> Binding;
        Prism::Contract::AccountAdmissionPermit Admission;
        std::size_t CredentialIndex{0U}; ///< 身份只借用该材料项，不维护第二份字符串。
        std::atomic<std::uint64_t> References{0U};
        std::atomic<std::uint64_t> Children{ClosedBit};
        std::atomic<bool> Connected{false};
        /** @brief root release封止新child，实际child退出后才归还连接额度。 */
        auto Close() noexcept -> void
        {
            const auto Before = Children.fetch_or(ClosedBit, std::memory_order_acq_rel);
            if ((Before & ~ClosedBit) == 0U) { ReleaseConnection(); }
        }
        [[nodiscard]] auto TryAttachChild() noexcept -> std::expected<void, Fault::Failure>
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
        auto DetachChild() noexcept -> void
        {
            const auto Before = Children.fetch_sub(1U, std::memory_order_acq_rel);
            if (Before == ClosedBit + 1U) { ReleaseConnection(); }
        }
        [[nodiscard]] auto Open() const noexcept -> bool { return (Children.load(std::memory_order_acquire) & ClosedBit) == 0U; }
    private:
        auto ReleaseConnection() noexcept -> void
        {
            if (Connected.exchange(false, std::memory_order_acq_rel)) { Binding->Runtime()->ReleaseConnection(); }
        }
    };
    /** @brief 冷分配槽/位图；共享总容量优先于每账户业务上限。 */
    class LeasePool final
    {
    public:
        explicit LeasePool(const std::size_t Capacity) : Capacity_(CheckedCapacity(Capacity)), WordCount_((Capacity_ + 63U) / 64U),
            Slots_(std::make_unique<RootLeaseSlot[]>(Capacity_)), Words_(std::make_unique<std::atomic<std::uint64_t>[]>(WordCount_)) {}
        /** @brief 最多每字四次CAS，不等待容量；失败明确ResourceUnavailable。 */
        [[nodiscard]] auto TryAcquire() noexcept -> std::expected<RootLeaseSlot*, Fault::Failure>
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
        auto Hold(RootLeaseSlot* Slot) noexcept -> void { Slot->References.fetch_add(1U, std::memory_order_relaxed); }
        /** @brief 最后元数据引用退栈后清理Binding并无分配归还槽。 */
        auto Release(RootLeaseSlot* Slot) noexcept -> void
        {
            if (!Slot || Slot->References.fetch_sub(1U, std::memory_order_acq_rel) != 1U) { return; }
            Slot->Close();
            Slot->Admission = {};
            Slot->Binding.reset();
            const auto Index = static_cast<std::size_t>(Slot - Slots_.get());
            Words_[Index / 64U].fetch_and(~(std::uint64_t{1U} << (Index % 64U)), std::memory_order_release);
        }
    private:
        [[nodiscard]] static auto CheckedCapacity(const std::size_t Capacity) -> std::size_t
        {
            if (Capacity == 0U || Capacity > 65536U) { throw std::invalid_argument("invalid account root lease capacity"); }
            return Capacity;
        }
        const std::size_t Capacity_, WordCount_;
        const std::unique_ptr<RootLeaseSlot[]> Slots_;
        const std::unique_ptr<std::atomic<std::uint64_t>[]> Words_;
        std::atomic<std::size_t> Hint_{0U};
    };
}
