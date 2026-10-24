/** @file LeasePool.hpp
 * @brief process 共享根账户 lease 槽，准入和归还无分配。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Account/Binding.hpp>
#include <Prism/Contract/Account/AdmissionAuthority.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <expected>

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
        auto Close() noexcept -> void;
        [[nodiscard]] auto TryAttachChild() noexcept -> std::expected<void, Fault::Failure>;
        auto DetachChild() noexcept -> void;
        [[nodiscard]] auto Open() const noexcept -> bool;
    private:
        auto ReleaseConnection() noexcept -> void;
    };
    /** @brief 冷分配槽/位图；共享总容量优先于每账户业务上限。 */
    class LeasePool final
    {
    public:
        explicit LeasePool(const std::size_t Capacity);
        /** @brief 最多每字四次CAS，不等待容量；失败明确ResourceUnavailable。 */
        [[nodiscard]] auto TryAcquire() noexcept -> std::expected<RootLeaseSlot*, Fault::Failure>;
        auto Hold(RootLeaseSlot* Slot) noexcept -> void;
        /** @brief 最后元数据引用退栈后清理Binding并无分配归还槽。 */
        auto Release(RootLeaseSlot* Slot) noexcept -> void;
    private:
        [[nodiscard]] static auto CheckedCapacity(const std::size_t Capacity) -> std::size_t;
        const std::size_t Capacity_, WordCount_;
        const std::unique_ptr<RootLeaseSlot[]> Slots_;
        const std::unique_ptr<std::atomic<std::uint64_t>[]> Words_;
        std::atomic<std::size_t> Hint_{0U};
    };
}
