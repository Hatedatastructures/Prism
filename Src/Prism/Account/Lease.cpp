/** @file Lease.cpp
 * @brief 根、子流与字节额度租约的状态访问实现。
 */
#include <Prism/Account/Lease.hpp>
#include <Prism/Account/Detail/LeasePool.hpp>
#include <Prism/Account/Failure.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <string_view>
#include <utility>

namespace Prism::Account
{
    ByteLease::ByteLease(ByteLease&& Other) noexcept
        : Binding_(std::move(Other.Binding_)), Amount_(std::exchange(Other.Amount_, 0U))
    {
    }

    auto ByteLease::operator=(ByteLease&& Other) noexcept -> ByteLease&
    {
        if (this != &Other)
        {
            Release();
            Binding_ = std::move(Other.Binding_);
            Amount_ = std::exchange(Other.Amount_, 0U);
        }
        return *this;
    }

    ByteLease::~ByteLease()
    {
        Release();
    }

    auto ByteLease::Release() noexcept -> void
    {
        if (Binding_)
        {
            Binding_->Runtime()->ReleaseBytes(Amount_);
            Binding_.reset();
            Amount_ = 0U;
        }
    }

    auto ByteLease::Size() const noexcept -> std::uint64_t
    {
        return Amount_;
    }

    auto ByteLease::Reduce(const std::uint64_t Amount) noexcept
        -> std::expected<void, Fault::Failure>
    {
        if (!Binding_ || Amount > Amount_)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        }
        Binding_->Runtime()->ReleaseBytes(Amount);
        Amount_ -= Amount;
        return {};
    }

    ByteLease::ByteLease(std::shared_ptr<const AccountBinding> Binding,
        const std::uint64_t Amount) noexcept
        : Binding_(std::move(Binding)), Amount_(Amount)
    {
    }

    StreamLease::StreamLease(StreamLease&& Other) noexcept
        : Pool_(std::move(Other.Pool_)), Slot_(std::exchange(Other.Slot_, nullptr)),
          Quota_(std::exchange(Other.Quota_, false)), Attached_(std::exchange(Other.Attached_, false))
    {
    }

    auto StreamLease::operator=(StreamLease&& Other) noexcept -> StreamLease&
    {
        if (this != &Other)
        {
            Release();
            Pool_ = std::move(Other.Pool_);
            Slot_ = std::exchange(Other.Slot_, nullptr);
            Quota_ = std::exchange(Other.Quota_, false);
            Attached_ = std::exchange(Other.Attached_, false);
        }
        return *this;
    }

    StreamLease::~StreamLease()
    {
        Release();
    }

    auto StreamLease::Release() noexcept -> void
    {
        if (!Slot_) { return; }
        if (Quota_) { Slot_->Binding->Runtime()->ReleaseStream(); }
        if (Attached_) { Slot_->DetachChild(); }
        Pool_->Release(Slot_);
        Slot_ = nullptr;
        Pool_.reset();
        Quota_ = false;
        Attached_ = false;
    }

    StreamLease::operator bool() const noexcept
    {
        return Slot_ && Quota_ && Attached_;
    }

    auto StreamLease::Binding() const noexcept -> std::shared_ptr<const AccountBinding>
    {
        if (Slot_) { return Slot_->Binding; }
        return {};
    }

    auto StreamLease::ReserveBytes(const std::uint64_t Amount) const noexcept
        -> std::expected<ByteLease, Fault::Failure>
    {
        if (!*this) { return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
        const auto Reserved = Slot_->Binding->Runtime()->ReserveBytes(
            Amount, Slot_->Binding->Policy()->Quota().MaxBytes);
        if (!Reserved) { return std::unexpected(Reserved.error()); }
        return ByteLease(Slot_->Binding, Amount);
    }

    StreamLease::StreamLease(std::shared_ptr<Detail::LeasePool> Pool,
        Detail::RootLeaseSlot* Slot) noexcept
        : Pool_(std::move(Pool)), Slot_(Slot)
    {
        Pool_->Hold(Slot_);
    }

    StreamAdmission::StreamAdmission(const StreamAdmission& Other) noexcept
        : Pool_(Other.Pool_), Slot_(Other.Slot_)
    {
        if (Slot_) { Pool_->Hold(Slot_); }
    }

    StreamAdmission::StreamAdmission(StreamAdmission&& Other) noexcept
        : Pool_(std::move(Other.Pool_)), Slot_(std::exchange(Other.Slot_, nullptr))
    {
    }

    auto StreamAdmission::operator=(StreamAdmission Other) noexcept -> StreamAdmission&
    {
        std::swap(Pool_, Other.Pool_);
        std::swap(Slot_, Other.Slot_);
        return *this;
    }

    StreamAdmission::~StreamAdmission()
    {
        if (Slot_) { Pool_->Release(Slot_); }
    }

    auto StreamAdmission::Acquire() const noexcept
        -> std::expected<StreamLease, Fault::Failure>
    {
        if (!Slot_ || !Slot_->Open())
        {
            return std::unexpected(Fault::Failure{Fault::Code::Canceled});
        }
        StreamLease Result(Pool_, Slot_);
        const auto Policy = Slot_->Binding->ResourcePolicy();
        if (!Policy) { return std::unexpected(Fault::Failure{Fault::Code::Forbidden}); }
        if (Policy->Settings().Transfer.TrafficBytes &&
            (!Slot_->Binding->Runtime()->Transfer() ||
                !Slot_->Binding->Runtime()->Transfer()->AdmissionAllowed()))
        {
            return std::unexpected(MakeFailure(FailureReason::ByteQuota));
        }
        auto Acquired = Slot_->Binding->Runtime()->TryAcquireStream(Policy->Quota().MaxStreams);
        if (!Acquired) { return std::unexpected(Acquired.error()); }
        Result.Quota_ = true;
        const auto Attached = Slot_->TryAttachChild();
        if (!Attached) { return std::unexpected(Attached.error()); }
        Result.Attached_ = true;
        Acquired->Commit();
        return Result;
    }

    auto StreamAdmission::Binding() const noexcept -> std::shared_ptr<const AccountBinding>
    {
        if (Slot_) { return Slot_->Binding; }
        return {};
    }

    StreamAdmission::operator bool() const noexcept
    {
        return Slot_ && Slot_->Open() && !Slot_->Binding->Runtime()->IsRevoked();
    }

    StreamAdmission::StreamAdmission(std::shared_ptr<Detail::LeasePool> Pool,
        Detail::RootLeaseSlot* Slot) noexcept
        : Pool_(std::move(Pool)), Slot_(Slot)
    {
        Pool_->Hold(Slot_);
    }

    AccountLease::AccountLease(AccountLease&& Other) noexcept
        : Pool_(std::move(Other.Pool_)), Slot_(std::exchange(Other.Slot_, nullptr))
    {
    }

    auto AccountLease::operator=(AccountLease&& Other) noexcept -> AccountLease&
    {
        if (this != &Other)
        {
            Release();
            Pool_ = std::move(Other.Pool_);
            Slot_ = std::exchange(Other.Slot_, nullptr);
        }
        return *this;
    }

    AccountLease::~AccountLease()
    {
        Release();
    }

    auto AccountLease::Release() noexcept -> void
    {
        if (Slot_)
        {
            Slot_->Close();
            Pool_->Release(Slot_);
            Slot_ = nullptr;
            Pool_.reset();
        }
    }

    AccountLease::operator bool() const noexcept
    {
        return Slot_ && Slot_->Connected.load(std::memory_order_acquire);
    }

    auto AccountLease::Binding() const noexcept -> std::shared_ptr<const AccountBinding>
    {
        if (Slot_) { return Slot_->Binding; }
        return {};
    }

    auto AccountLease::AccountId() const noexcept -> Prism::AccountId
    {
        if (Slot_) { return Slot_->Binding->AccountId(); }
        return {};
    }

    auto AccountLease::PolicyVersion() const noexcept -> Prism::Account::PolicyVersion
    {
        if (Slot_) { return Slot_->Binding->Policy()->Version(); }
        return {};
    }

    auto AccountLease::RuntimeIdentity() const noexcept -> AccountRuntimeIdentity
    {
        if (Slot_) { return Slot_->Binding->Runtime()->RuntimeIdentity(); }
        return {};
    }

    auto AccountLease::Identity() const noexcept -> std::string_view
    {
        if (Slot_) { return Slot_->Binding->Materials()->Credentials()[Slot_->CredentialIndex].Identity; }
        return {};
    }

    auto AccountLease::DisplayIdentity() const noexcept -> std::string_view
    {
        if (Slot_) { return Slot_->Binding->Materials()->DisplayIdentity(); }
        return {};
    }

    auto AccountLease::Streams() const noexcept -> StreamAdmission
    {
        if (*this) { return StreamAdmission(Pool_, Slot_); }
        return {};
    }

    auto AccountLease::TryAcquireStream() const noexcept
        -> std::expected<StreamLease, Fault::Failure>
    {
        return Streams().Acquire();
    }

    auto AccountLease::ReserveBytes(const std::uint64_t Amount) const noexcept
        -> std::expected<ByteLease, Fault::Failure>
    {
        if (!*this) { return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
        const auto Reserved = Slot_->Binding->Runtime()->ReserveBytes(
            Amount, Slot_->Binding->Policy()->Quota().MaxBytes);
        if (!Reserved) { return std::unexpected(Reserved.error()); }
        return ByteLease(Slot_->Binding, Amount);
    }

    AccountLease::AccountLease(std::shared_ptr<Detail::LeasePool> Pool,
        Detail::RootLeaseSlot* Slot) noexcept
        : Pool_(std::move(Pool)), Slot_(Slot)
    {
    }
}
