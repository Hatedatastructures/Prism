/** @file Lease.hpp
 * @brief 根、子流和字节额度的唯一拥有型预约。
 */
#pragma once
#include <Preview/Account/Detail/LeasePool.hpp>
#include <expected>
#include <memory>
#include <utility>

namespace Preview::Account
{
    class AccountStore;
    class AccountLease;
    class StreamAdmission;
    /** @brief move-only字节额度；最后拥有者归还，不管理I/O关闭或executor。 */
    class ByteLease final
    {
    public:
        ByteLease() = default;
        ByteLease(const ByteLease&) = delete;
        auto operator=(const ByteLease&) -> ByteLease& = delete;
        ByteLease(ByteLease&& Other) noexcept : Binding_(std::move(Other.Binding_)), Amount_(std::exchange(Other.Amount_, 0U)) {}
        auto operator=(ByteLease&& Other) noexcept -> ByteLease&
        {
            if (this != &Other) { Release(); Binding_ = std::move(Other.Binding_); Amount_ = std::exchange(Other.Amount_, 0U); }
            return *this;
        }
        ~ByteLease() { Release(); }
        auto Release() noexcept -> void
        {
            if (Binding_) { Binding_->Runtime()->ReleaseBytes(Amount_); Binding_.reset(); Amount_ = 0U; }
        }
        [[nodiscard]] auto Size() const noexcept -> std::uint64_t { return Amount_; }
        /** @brief 只归还本ticket实际拥有的部分；超过拥有量拒绝，不提前清零其他owner。 */
        [[nodiscard]] auto Reduce(const std::uint64_t Amount) noexcept -> std::expected<void, Fault::Failure>
        {
            if (!Binding_ || Amount > Amount_) { return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument}); }
            Binding_->Runtime()->ReleaseBytes(Amount);
            Amount_ -= Amount;
            return {};
        }
    private:
        friend class AccountLease;
        friend class StreamLease;
        ByteLease(std::shared_ptr<const AccountBinding> Binding, const std::uint64_t Amount) noexcept
            : Binding_(std::move(Binding)), Amount_(Amount) {}
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
        StreamLease(StreamLease&& Other) noexcept : Pool_(std::move(Other.Pool_)), Slot_(std::exchange(Other.Slot_, nullptr)),
            Quota_(std::exchange(Other.Quota_, false)), Attached_(std::exchange(Other.Attached_, false)) {}
        auto operator=(StreamLease&& Other) noexcept -> StreamLease&
        {
            if (this != &Other)
            {
                Release(); Pool_ = std::move(Other.Pool_); Slot_ = std::exchange(Other.Slot_, nullptr);
                Quota_ = std::exchange(Other.Quota_, false); Attached_ = std::exchange(Other.Attached_, false);
            }
            return *this;
        }
        ~StreamLease() { Release(); }
        auto Release() noexcept -> void
        {
            if (!Slot_) { return; }
            if (Quota_) { Slot_->Binding->Runtime()->ReleaseStream(); }
            if (Attached_) { Slot_->DetachChild(); }
            Pool_->Release(Slot_); Slot_ = nullptr; Pool_.reset(); Quota_ = false; Attached_ = false;
        }
        explicit operator bool() const noexcept { return Slot_ && Quota_ && Attached_; }
        [[nodiscard]] auto Binding() const noexcept -> std::shared_ptr<const AccountBinding>
        {
            if (Slot_) { return Slot_->Binding; }
            return {};
        }
        [[nodiscard]] auto ReserveBytes(const std::uint64_t Amount) const noexcept -> std::expected<ByteLease, Fault::Failure>
        {
            if (!*this) { return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
            const auto Reserved = Slot_->Binding->Runtime()->ReserveBytes(Amount, Slot_->Binding->Policy()->Quota().MaxBytes);
            if (!Reserved) { return std::unexpected(Reserved.error()); }
            return ByteLease(Slot_->Binding, Amount);
        }
    private:
        friend class StreamAdmission;
        StreamLease(std::shared_ptr<Detail::LeasePool> Pool, Detail::RootLeaseSlot* Slot) noexcept
            : Pool_(std::move(Pool)), Slot_(Slot) { Pool_->Hold(Slot_); }
        std::shared_ptr<Detail::LeasePool> Pool_;
        Detail::RootLeaseSlot* Slot_{nullptr};
        bool Quota_{false}, Attached_{false};
    };
    /** @brief 根派生的窄child能力；copy只pin实际槽，不能复制根quota或重认证。 */
    class StreamAdmission final
    {
    public:
        StreamAdmission() = default;
        StreamAdmission(const StreamAdmission& Other) noexcept : Pool_(Other.Pool_), Slot_(Other.Slot_)
        { if (Slot_) { Pool_->Hold(Slot_); } }
        StreamAdmission(StreamAdmission&& Other) noexcept : Pool_(std::move(Other.Pool_)), Slot_(std::exchange(Other.Slot_, nullptr)) {}
        auto operator=(StreamAdmission Other) noexcept -> StreamAdmission&
        { std::swap(Pool_, Other.Pool_); std::swap(Slot_, Other.Slot_); return *this; }
        ~StreamAdmission() { if (Slot_) { Pool_->Release(Slot_); } }
        /** @brief 账户/根两层撤销门禁，拒绝与最终commit失败均由立即成立的owner回滚。 */
        [[nodiscard]] auto Acquire() const noexcept -> std::expected<StreamLease, Fault::Failure>
        {
            if (!Slot_ || !Slot_->Open()) { return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
            StreamLease Result(Pool_, Slot_);
            auto Acquired = Slot_->Binding->Runtime()->TryAcquireStream(Slot_->Binding->Policy()->Quota().MaxStreams);
            if (!Acquired) { return std::unexpected(Acquired.error()); }
            Result.Quota_ = true;
            const auto Attached = Slot_->TryAttachChild();
            if (!Attached) { return std::unexpected(Attached.error()); }
            Result.Attached_ = true;
            Acquired->Commit();
            return Result;
        }
        [[nodiscard]] auto Binding() const noexcept -> std::shared_ptr<const AccountBinding>
        { if (Slot_) { return Slot_->Binding; } return {}; }
        explicit operator bool() const noexcept { return Slot_ && Slot_->Open() && !Slot_->Binding->Runtime()->IsRevoked(); }
    private:
        friend class AccountLease;
        StreamAdmission(std::shared_ptr<Detail::LeasePool> Pool, Detail::RootLeaseSlot* Slot) noexcept
            : Pool_(std::move(Pool)), Slot_(Slot) { Pool_->Hold(Slot_); }
        std::shared_ptr<Detail::LeasePool> Pool_;
        Detail::RootLeaseSlot* Slot_{nullptr};
    };
    /**
     * @brief 根连接lease；pins唯一Binding和实际pool，成功后不再猜材料/策略代次。
     * @details Release封止child而不关闭I/O；最后实际child退出才归还连接额度。
     *          单对象不允许并发move/release，协议owner在其executor管理I/O最终关闭和任务drain。
     */
    class AccountLease final
    {
    public:
        AccountLease() = default;
        AccountLease(const AccountLease&) = delete;
        auto operator=(const AccountLease&) -> AccountLease& = delete;
        AccountLease(AccountLease&& Other) noexcept : Pool_(std::move(Other.Pool_)), Slot_(std::exchange(Other.Slot_, nullptr)) {}
        auto operator=(AccountLease&& Other) noexcept -> AccountLease&
        {
            if (this != &Other) { Release(); Pool_ = std::move(Other.Pool_); Slot_ = std::exchange(Other.Slot_, nullptr); }
            return *this;
        }
        ~AccountLease() { Release(); }
        auto Release() noexcept -> void
        {
            if (Slot_) { Slot_->Close(); Pool_->Release(Slot_); Slot_ = nullptr; Pool_.reset(); }
        }
        explicit operator bool() const noexcept { return Slot_ && Slot_->Connected.load(std::memory_order_acquire); }
        [[nodiscard]] auto Binding() const noexcept -> std::shared_ptr<const AccountBinding>
        { if (Slot_) { return Slot_->Binding; } return {}; }
        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        { if (Slot_) { return Slot_->Binding->AccountId(); } return {}; }
        [[nodiscard]] auto PolicyVersion() const noexcept -> Preview::Account::PolicyVersion
        { if (Slot_) { return Slot_->Binding->Policy()->Version(); } return {}; }
        /** @brief 返回固定 Binding 所属 runtime 的唯一身份，不借用策略版本充当代次。 */
        [[nodiscard]] auto RuntimeIdentity() const noexcept -> AccountRuntimeIdentity
        {
            if (Slot_) { return Slot_->Binding->Runtime()->RuntimeIdentity(); }
            return {};
        }
        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        { if (Slot_) { return Slot_->Binding->Materials()->Credentials()[Slot_->CredentialIndex].Identity; } return {}; }
        [[nodiscard]] auto DisplayIdentity() const noexcept -> std::string_view
        { if (Slot_) { return Slot_->Binding->Materials()->DisplayIdentity(); } return {}; }
        [[nodiscard]] auto Streams() const noexcept -> StreamAdmission
        { if (*this) { return StreamAdmission(Pool_, Slot_); } return {}; }
        [[nodiscard]] auto TryAcquireStream() const noexcept -> std::expected<StreamLease, Fault::Failure>
        { return Streams().Acquire(); }
        [[nodiscard]] auto ReserveBytes(const std::uint64_t Amount) const noexcept -> std::expected<ByteLease, Fault::Failure>
        {
            if (!*this) { return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
            const auto Reserved = Slot_->Binding->Runtime()->ReserveBytes(Amount, Slot_->Binding->Policy()->Quota().MaxBytes);
            if (!Reserved) { return std::unexpected(Reserved.error()); }
            return ByteLease(Slot_->Binding, Amount);
        }
    private:
        friend class AccountStore;
        friend class CredentialIndexView;
        AccountLease(std::shared_ptr<Detail::LeasePool> Pool, Detail::RootLeaseSlot* Slot) noexcept
            : Pool_(std::move(Pool)), Slot_(Slot) {}
        std::shared_ptr<Detail::LeasePool> Pool_;
        Detail::RootLeaseSlot* Slot_{nullptr};
    };
}
