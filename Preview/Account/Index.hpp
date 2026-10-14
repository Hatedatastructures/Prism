/** @file Index.hpp
 * @brief 热认证的预编译凭据域视图与单次快照消费。
 */
#pragma once
#include <Preview/Account/Failure.hpp>
#include <Preview/Account/Lease.hpp>
#include <Preview/Foundation/Utility/Crypto/Hkdf.hpp>
#include <array>
#include <algorithm>
#include <atomic>
#include <expected>
#include <memory>
#include <vector>
#include <type_traits>

namespace Preview::Account
{
    class AccountStore;
    /** @brief 同步认证输入；不保存Credential或Identity借用，不包含配置/服务定位器。 */
    struct AcquireRequest final
    {
        Preview::AccountId AccountId{};
        std::string_view Identity;
        CredentialView Credential;
        RateRequest Rate;
        Preview::Account::PolicyVersion RequiredPolicyVersion{}; ///< 非零要求账户策略版本，不能填应用generation。
    };
    namespace Detail
    {
        using CredentialDigest = std::array<std::uint8_t, 32U>;
        struct CredentialIndexEntry final
        {
            CredentialDigest Digest;
            CredentialKind Kind;
            std::shared_ptr<const AccountBinding> Binding;
            std::size_t MaterialIndex;
        };
        struct CredentialIndex final { std::vector<CredentialIndexEntry> Entries; };
        [[nodiscard]] inline auto CredentialKeyLess(const CredentialIndexEntry& Left,
            const CredentialIndexEntry& Right) noexcept -> bool
        {
            if (Left.Kind != Right.Kind) { return Left.Kind < Right.Kind; }
            return Left.Digest < Right.Digest;
        }
        [[nodiscard]] inline auto CredentialRange(const CredentialIndex& Index,
            const CredentialIndexEntry& Key) noexcept -> std::span<const CredentialIndexEntry>
        {
            const auto Begin = std::lower_bound(Index.Entries.begin(), Index.Entries.end(), Key, CredentialKeyLess);
            auto End = Begin;
            while (End != Index.Entries.end() && End->Kind == Key.Kind && End->Digest == Key.Digest) { ++End; }
            return {Begin, End};
        }
        struct AccountSnapshot final
        {
            std::vector<std::shared_ptr<const AccountBinding>> Bindings;
            std::array<std::shared_ptr<const CredentialIndex>, 64U> Indexes;
        };
        struct AccountStoreState final
        {
            std::atomic<bool> Accepting{true};
            std::atomic<std::shared_ptr<const AccountSnapshot>> Snapshot;
            const std::shared_ptr<LeasePool> Leases;
            const std::size_t CredentialBytes;
            AccountStoreState(std::shared_ptr<LeasePool> Pool, const std::size_t Maximum)
                : Snapshot(std::make_shared<const AccountSnapshot>()), Leases(std::move(Pool)), CredentialBytes(Maximum) {}
        };
        [[nodiscard]] inline auto DigestCredential(const CredentialView Value) noexcept
            -> std::expected<CredentialDigest, Fault::Failure>
        {
            const auto Bytes = Value.Bytes();
            return Crypto::Sha256(std::span(reinterpret_cast<const std::uint8_t*>(Bytes.data()), Bytes.size()));
        }
    }
    /**
     * @brief 冷得到固定ordinal，热只读一个完整snapshot及该ordinal的已编译index。
     * @details view拥有process store state，协议不按名称找realm。材料、policy、runtime从同一Binding得到。
     *          Inspect不取lease或rate；TryAcquire立即保护quota/pool/rate预约，失败退栈全部回滚。
     *          同步函数不跨异步借用、不关闭I/O、无executor要求，实际最终关闭仍归协议owner。
     */
    class CredentialIndexView final
    {
        using Failure = Fault::Failure;
    public:
        CredentialIndexView() = default;
        [[nodiscard]] auto InspectCredential(const CredentialView Credential) const noexcept -> std::expected<bool, Failure>
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
        /** @brief 冷枚举此scope的指定材料种类，回调同步借用两个正式值，Snapshot保持到全部回调返回。 */
        template <typename Function>
            requires std::is_same_v<std::invoke_result_t<Function&,
                const std::shared_ptr<const AccountBinding>&, const CredentialMaterial&>, void>
        [[nodiscard]] auto ForEachCredential(const CredentialKind Kind, Function&& Visitor) const
            -> std::expected<void, Failure>
        {
            if (!State_) { return std::unexpected(Failure{Fault::Code::ResourceUnavailable}); }
            const auto Snapshot = State_->Snapshot.load(std::memory_order_acquire);
            const auto& Index = Snapshot->Indexes[Ordinal_];
            if (Index)
            {
                for (const auto& Entry : Index->Entries)
                {
                    if (Entry.Kind == Kind) { Visitor(Entry.Binding, Entry.Binding->Materials()->Credentials()[Entry.MaterialIndex]); }
                }
            }
            return {};
        }
        [[nodiscard]] auto TryAcquire(const AcquireRequest& Request) const noexcept -> std::expected<AccountLease, Failure>
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
            auto Connection = Runtime->TryAcquireConnection(Entry.Binding->Policy()->Quota().MaxConnections);
            if (!Connection) { return std::unexpected(Connection.error()); }
            (*Slot)->Admission = std::move(*Connection);
            (*Slot)->Connected.store(true, std::memory_order_release);
            auto Rate = Entry.Binding->Policy()->Rate()->TryReserve(Request.Rate);
            if (!Rate) { return std::unexpected(Rate.error()); }
            if (!State_->Accepting.load(std::memory_order_acquire)) { return std::unexpected(Failure{Fault::Code::Canceled}); }
            Rate->Commit();
            (*Slot)->Admission.Commit();
            return Lease;
        }
        explicit operator bool() const noexcept { return static_cast<bool>(State_); }
    private:
        friend class AccountStore;
        CredentialIndexView(std::shared_ptr<Detail::AccountStoreState> State, const std::size_t Ordinal) noexcept
            : State_(std::move(State)), Ordinal_(Ordinal) {}
        [[nodiscard]] static auto EqualIdentity(const std::string_view Left, const std::string_view Right) noexcept -> bool
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
        [[nodiscard]] auto Find(const AcquireRequest& Request) const noexcept
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
            for (const auto& Entry : Detail::CredentialRange(*Index, Key))
            {
                if (Entry.Kind != Request.Credential.Kind() || Entry.Digest != *Digest) { continue; }
                const auto& Material = Entry.Binding->Materials()->Credentials()[Entry.MaterialIndex];
                if (!Material.Credential.Matches(Request.Credential) ||
                    (!Material.Identity.empty() && !EqualIdentity(Material.Identity, Request.Identity))) { continue; }
                if (Request.AccountId && Request.AccountId != Entry.Binding->AccountId()) { continue; }
                if (Request.RequiredPolicyVersion && Request.RequiredPolicyVersion != Entry.Binding->Policy()->Version())
                { return std::unexpected(MakeFailure(FailureReason::PolicyMismatch)); }
                return Entry;
            }
            return std::unexpected(MakeFailure(FailureReason::NotFound));
        }
        std::shared_ptr<Detail::AccountStoreState> State_;
        std::size_t Ordinal_{0U};
    };
}
