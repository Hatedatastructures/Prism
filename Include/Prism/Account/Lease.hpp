/** @file Lease.hpp
 * @brief 根、子流和字节额度的唯一拥有型预约。
 */
#pragma once
#include <Prism/Account/Binding.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <string_view>

namespace Prism::Account
{
    namespace Detail { class LeasePool; struct RootLeaseSlot; }
    class AccountStore;
    class AccountLease;
    class StreamAdmission;
    /** @brief 仅可移动的字节额度；最后一个拥有者归还，不负责 I/O 关闭或 executor。 */
    class ByteLease final
    {
    public:
        ByteLease() = default;
        ByteLease(const ByteLease&) = delete;
        auto operator=(const ByteLease&) -> ByteLease& = delete;
        ByteLease(ByteLease&& Other) noexcept;
        auto operator=(ByteLease&& Other) noexcept -> ByteLease&;
        ~ByteLease();
        auto Release() noexcept -> void;
        [[nodiscard]] auto Size() const noexcept -> std::uint64_t;
        /** @brief 只归还当前 lease 实际持有的部分；超过持有量时拒绝，不影响其他 owner。 */
        [[nodiscard]] auto Reduce(const std::uint64_t Amount) noexcept
            -> std::expected<void, Fault::Failure>;
    private:
        friend class AccountLease;
        friend class StreamLease;
        ByteLease(std::shared_ptr<const AccountBinding> Binding, const std::uint64_t Amount) noexcept;
        std::shared_ptr<const AccountBinding> Binding_;
        std::uint64_t Amount_{0U};
    };
    /** @brief 已实际取得的child额度，root释放后仍保活根连接额度至自身退出。 */
    class StreamLease final
    {
    public:
        StreamLease() = default;
        StreamLease(const StreamLease&) = delete;
        auto operator=(const StreamLease&) -> StreamLease& = delete;
        StreamLease(StreamLease&& Other) noexcept;
        auto operator=(StreamLease&& Other) noexcept -> StreamLease&;
        ~StreamLease();
        auto Release() noexcept -> void;
        explicit operator bool() const noexcept;
        [[nodiscard]] auto Binding() const noexcept -> std::shared_ptr<const AccountBinding>;
        [[nodiscard]] auto ReserveBytes(const std::uint64_t Amount) const noexcept
            -> std::expected<ByteLease, Fault::Failure>;
    private:
        friend class StreamAdmission;
        StreamLease(std::shared_ptr<Detail::LeasePool> Pool, Detail::RootLeaseSlot* Slot) noexcept;
        std::shared_ptr<Detail::LeasePool> Pool_;
        Detail::RootLeaseSlot* Slot_{nullptr};
        bool Quota_{false}, Attached_{false};
    };
    /** @brief 根派生的窄child能力；copy只pin实际槽，不能复制根quota或重认证。 */
    class StreamAdmission final
    {
    public:
        StreamAdmission() = default;
        StreamAdmission(const StreamAdmission& Other) noexcept;
        StreamAdmission(StreamAdmission&& Other) noexcept;
        auto operator=(StreamAdmission Other) noexcept -> StreamAdmission&;
        ~StreamAdmission();
        /** @brief 账户/根两层撤销门禁，拒绝与最终commit失败均由立即成立的owner回滚。 */
        [[nodiscard]] auto Acquire() const noexcept -> std::expected<StreamLease, Fault::Failure>;
        [[nodiscard]] auto Binding() const noexcept -> std::shared_ptr<const AccountBinding>;
        explicit operator bool() const noexcept;
    private:
        friend class AccountLease;
        StreamAdmission(std::shared_ptr<Detail::LeasePool> Pool, Detail::RootLeaseSlot* Slot) noexcept;
        std::shared_ptr<Detail::LeasePool> Pool_;
        Detail::RootLeaseSlot* Slot_{nullptr};
    };
    /**
     * @brief 根连接租约；固定唯一 Binding 和实际池，绑定成功后不按后续代次重新推断认证事实。
     * @details Release 会封止新 child，但不关闭 I/O；最后一个实际 child 退出后才归还连接额度。
     *          同一对象不支持并发移动或释放；协议 owner 在所属 executor 上管理最终 I/O 关闭和任务排空。
     */
    class AccountLease final
    {
    public:
        AccountLease() = default;
        AccountLease(const AccountLease&) = delete;
        auto operator=(const AccountLease&) -> AccountLease& = delete;
        AccountLease(AccountLease&& Other) noexcept;
        auto operator=(AccountLease&& Other) noexcept -> AccountLease&;
        ~AccountLease();
        auto Release() noexcept -> void;
        explicit operator bool() const noexcept;
        [[nodiscard]] auto Binding() const noexcept -> std::shared_ptr<const AccountBinding>;
        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId;
        [[nodiscard]] auto PolicyVersion() const noexcept -> Prism::Account::PolicyVersion;
        /** @brief 返回固定 Binding 所属 runtime 的唯一身份，不借用策略版本充当代次。 */
        [[nodiscard]] auto RuntimeIdentity() const noexcept -> AccountRuntimeIdentity;
        [[nodiscard]] auto Identity() const noexcept -> std::string_view;
        [[nodiscard]] auto DisplayIdentity() const noexcept -> std::string_view;
        [[nodiscard]] auto Streams() const noexcept -> StreamAdmission;
        [[nodiscard]] auto TryAcquireStream() const noexcept
            -> std::expected<StreamLease, Fault::Failure>;
        [[nodiscard]] auto ReserveBytes(const std::uint64_t Amount) const noexcept
            -> std::expected<ByteLease, Fault::Failure>;
    private:
        friend class AccountStore;
        friend class CredentialIndexView;
        AccountLease(std::shared_ptr<Detail::LeasePool> Pool, Detail::RootLeaseSlot* Slot) noexcept;
        std::shared_ptr<Detail::LeasePool> Pool_;
        Detail::RootLeaseSlot* Slot_{nullptr};
    };
}
