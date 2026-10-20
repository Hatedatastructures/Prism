/** @file AccountAdmission.cpp @brief admission/publication 并发预约与许可实现。 */
#include <Prism/Contract/Account/AdmissionAuthority.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Contract
{
    auto AccountAdmissionGate::TryBeginAdmission() noexcept -> bool
    {
        auto Current = State_.load(std::memory_order_acquire);
        while ((Current & PublicationBit) == 0U && Current != PublicationBit - 1U)
        {
            if (State_.compare_exchange_weak(Current, Current + 1U,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return true;
            }
        }
        return false;
    }

    auto AccountAdmissionGate::TryBeginPublication() noexcept -> bool
    {
        std::uint64_t Expected = 0U;
        return State_.compare_exchange_strong(Expected, PublicationBit,
            std::memory_order_acq_rel, std::memory_order_acquire);
    }

    auto AccountAdmissionGate::EndPublication() noexcept -> void
    {
        State_.store(0U, std::memory_order_release);
    }

    auto AccountAdmissionGate::ReleaseAccountAdmission() noexcept -> void
    {
        State_.fetch_sub(1U, std::memory_order_release);
    }

    AccountAdmissionPermit::AccountAdmissionPermit(
        std::shared_ptr<AccountAdmissionLeaseOwner> OwnerValue) noexcept
        : Owner_(std::move(OwnerValue))
    {
    }

    AccountAdmissionPermit::AccountAdmissionPermit(AccountAdmissionPermit &&Other) noexcept
        : Owner_(std::move(Other.Owner_))
    {
    }

    auto AccountAdmissionPermit::operator=(AccountAdmissionPermit &&Other) noexcept
        -> AccountAdmissionPermit &
    {
        if (this != &Other)
        {
            Reset();
            Owner_ = std::move(Other.Owner_);
        }
        return *this;
    }

    AccountAdmissionPermit::~AccountAdmissionPermit() noexcept
    {
        Reset();
    }

    auto AccountAdmissionPermit::Commit() noexcept -> void
    {
        Reset();
    }

    auto AccountAdmissionPermit::Reset() noexcept -> void
    {
        if (Owner_)
        {
            auto Owner = std::move(Owner_);
            Owner->ReleaseAccountAdmission();
        }
    }
}
