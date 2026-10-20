/** @file Index.cpp
 * @brief 凭据索引视图的匹配与准入实现。
 */
#include <Prism/Account/Index.hpp>
#include <Prism/Account/Detail/LeasePool.hpp>
#include <Prism/Foundation/Utility/Crypto/Hkdf.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

namespace Prism::Account
{
        auto CredentialIndexView::InspectCredential(const CredentialView Credential) const noexcept -> std::expected<bool, Failure>
        {
            if (!State_) { return std::unexpected(Failure{Fault::Code::ResourceUnavailable}); }
            if (!State_->Accepting.load(std::memory_order_acquire)) { return std::unexpected(Failure{Fault::Code::Canceled}); }
            if (!Credential.IsValid() || Credential.Size() > State_->CredentialBytes) { return std::unexpected(MakeFailure(FailureReason::InvalidCredential)); }
            const auto Digest = Detail::DigestCredential(Credential);
            if (!Digest) { return std::unexpected(Digest.error()); }
            const auto Snapshot = State_->Snapshot.load(std::memory_order_acquire);
            const auto& Index = Snapshot->Indexes[Ordinal_];
            if (!Index) { return false; }
            const Detail::CredentialIndexEntry Key{*Digest, Credential.Kind(), {}, 0U};
            for (const auto& Entry : Detail::CredentialRange(*Index, Key))
            {
                if (Entry.Kind == Credential.Kind() && Entry.Digest == *Digest &&
                    Entry.Binding->Materials()->Credentials()[Entry.MaterialIndex].Credential.Matches(Credential)) { return true; }
            }
            return false;
        }

        auto CredentialIndexView::TryAcquire(const AcquireRequest& Request) const noexcept -> std::expected<AccountLease, Failure>
        {
            const auto Found = Find(Request);
            if (!Found) { return std::unexpected(Found.error()); }
            const auto& Entry = *Found;
            const auto Slot = State_->Leases->TryAcquire();
            if (!Slot) { return std::unexpected(Slot.error()); }
            AccountLease Lease(State_->Leases, *Slot);
            (*Slot)->Binding = Entry.Binding;
            (*Slot)->CredentialIndex = Entry.MaterialIndex;
            const auto& Runtime = Entry.Binding->Runtime();
            const auto Policy = Entry.Binding->ResourcePolicy();
            if (!Policy) return std::unexpected(Failure{Fault::Code::Forbidden});
            if (Policy->Settings().Transfer.TrafficBytes &&
                (!Runtime->Transfer() || !Runtime->Transfer()->AdmissionAllowed()))
                return std::unexpected(MakeFailure(FailureReason::ByteQuota));
            auto Connection = Runtime->TryAcquireConnection(Policy->Quota().MaxConnections);
            if (!Connection) { return std::unexpected(Connection.error()); }
            (*Slot)->Admission = std::move(*Connection);
            (*Slot)->Connected.store(true, std::memory_order_release);
            auto Input = Request.Rate;
            if (Input.Now == 0U) Input.Now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            auto Rate = Policy->Rate()->TryReserve(Input);
            if (!Rate) { return std::unexpected(Rate.error()); }
            if (!State_->Accepting.load(std::memory_order_acquire)) { return std::unexpected(Failure{Fault::Code::Canceled}); }
            Rate->Commit();
            (*Slot)->Admission.Commit();
            return Lease;
        }

        CredentialIndexView::operator bool() const noexcept { return static_cast<bool>(State_); }

        CredentialIndexView::CredentialIndexView(std::shared_ptr<Detail::AccountStoreState> State, const std::size_t Ordinal) noexcept
            : State_(std::move(State)), Ordinal_(Ordinal) {}

        auto CredentialIndexView::EqualIdentity(const std::string_view Left, const std::string_view Right) noexcept -> bool
        {
            std::uint8_t Difference = static_cast<std::uint8_t>(Left.size() != Right.size());
            const auto Length = (std::max)(Left.size(), Right.size());
            for (std::size_t Index = 0U; Index < Length; ++Index)
            {
                std::uint8_t A = 0U, B = 0U;
                if (Index < Left.size()) { A = static_cast<std::uint8_t>(Left[Index]); }
                if (Index < Right.size()) { B = static_cast<std::uint8_t>(Right[Index]); }
                Difference = static_cast<std::uint8_t>(Difference | (A ^ B));
            }
            return Difference == 0U;
        }

        auto CredentialIndexView::Find(const AcquireRequest& Request) const noexcept
            -> std::expected<Detail::CredentialIndexEntry, Failure>
        {
            if (!State_) { return std::unexpected(Failure{Fault::Code::ResourceUnavailable}); }
            if (!State_->Accepting.load(std::memory_order_acquire)) { return std::unexpected(Failure{Fault::Code::Canceled}); }
            if (!Request.Credential.IsValid()) { return std::unexpected(MakeFailure(FailureReason::InvalidCredential)); }
            if (Request.Credential.Size() > State_->CredentialBytes || Request.Identity.size() > State_->CredentialBytes)
            { return std::unexpected(Failure{Fault::Code::OversizedMsg}); }
            const auto Digest = Detail::DigestCredential(Request.Credential);
            if (!Digest) { return std::unexpected(Digest.error()); }
            const auto Snapshot = State_->Snapshot.load(std::memory_order_acquire);
            const auto& Index = Snapshot->Indexes[Ordinal_];
            if (!Index) { return std::unexpected(MakeFailure(FailureReason::NotFound)); }
            const Detail::CredentialIndexEntry Key{*Digest, Request.Credential.Kind(), {}, 0U};
            const Detail::CredentialIndexEntry* Match{};
            bool PolicyMismatch = false;
            for (const auto& Entry : Detail::CredentialRange(*Index, Key))
            {
                if (Entry.Kind != Request.Credential.Kind() || Entry.Digest != *Digest) { continue; }
                const auto& Material = Entry.Binding->Materials()->Credentials()[Entry.MaterialIndex];
                if (!Material.Credential.Matches(Request.Credential) ||
                    (!Request.Identity.empty() && !Material.Identity.empty() &&
                     !EqualIdentity(Material.Identity, Request.Identity)) ||
                    (Request.AccountId && Request.AccountId != Entry.Binding->AccountId())) { continue; }
                if (Request.RequiredPolicyVersion && Request.RequiredPolicyVersion != Entry.Binding->Policy()->Version())
                {
                    PolicyMismatch = true;
                    continue;
                }
                if (Match) { return std::unexpected(MakeFailure(FailureReason::InvalidCredential)); }
                Match = &Entry;
            }
            if (Match) { return *Match; }
            if (PolicyMismatch) { return std::unexpected(MakeFailure(FailureReason::PolicyMismatch)); }
            return std::unexpected(MakeFailure(FailureReason::NotFound));
        }
    namespace Detail
    {
            AccountStoreState::AccountStoreState(std::shared_ptr<LeasePool> Pool, const std::size_t Maximum)
                : Snapshot(std::make_shared<const AccountSnapshot>()), Leases(std::move(Pool)), CredentialBytes(Maximum) {}

        auto CredentialKeyLess(const CredentialIndexEntry& Left,
            const CredentialIndexEntry& Right) noexcept -> bool
        {
            if (Left.Kind != Right.Kind) { return Left.Kind < Right.Kind; }
            return Left.Digest < Right.Digest;
        }

        auto CredentialRange(const CredentialIndex& Index,
            const CredentialIndexEntry& Key) noexcept -> std::span<const CredentialIndexEntry>
        {
            const auto Begin = std::lower_bound(Index.Entries.begin(), Index.Entries.end(), Key, CredentialKeyLess);
            auto End = Begin;
            while (End != Index.Entries.end() && End->Kind == Key.Kind && End->Digest == Key.Digest) { ++End; }
            return {Begin, End};
        }

        auto DigestCredential(const CredentialView Value) noexcept
            -> std::expected<CredentialDigest, Fault::Failure>
        {
            const auto Bytes = Value.Bytes();
            return Crypto::Sha256(std::span(reinterpret_cast<const std::uint8_t*>(Bytes.data()), Bytes.size()));
        }
    }
}
