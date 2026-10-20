/** @file Index.hpp
 * @brief 热认证的预编译凭据域视图与单次快照消费。
 */
#pragma once
#include <Prism/Account/Failure.hpp>
#include <Prism/Account/Lease.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <vector>
#include <type_traits>

namespace Prism::Account
{
    class AccountStore;
    /** @brief 同步认证输入；不保存Credential或Identity借用，不包含配置/服务定位器。 */
    struct AcquireRequest final
    {
        Prism::AccountId AccountId{};
        std::string_view Identity;
        CredentialView Credential;
        RateRequest Rate;
        Prism::Account::PolicyVersion RequiredPolicyVersion{}; ///< 非零要求账户策略版本，不能填应用generation。
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
        [[nodiscard]] auto CredentialKeyLess(const CredentialIndexEntry& Left,
            const CredentialIndexEntry& Right) noexcept -> bool;
        [[nodiscard]] auto CredentialRange(const CredentialIndex& Index,
            const CredentialIndexEntry& Key) noexcept -> std::span<const CredentialIndexEntry>;
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
            AccountStoreState(std::shared_ptr<LeasePool> Pool, const std::size_t Maximum);
        };
        [[nodiscard]] auto DigestCredential(const CredentialView Value) noexcept
            -> std::expected<CredentialDigest, Fault::Failure>;
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
        [[nodiscard]] auto InspectCredential(const CredentialView Credential) const noexcept -> std::expected<bool, Failure>;
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
        [[nodiscard]] auto TryAcquire(const AcquireRequest& Request) const noexcept -> std::expected<AccountLease, Failure>;
        explicit operator bool() const noexcept;
    private:
        friend class AccountStore;
        CredentialIndexView(std::shared_ptr<Detail::AccountStoreState> State, const std::size_t Ordinal) noexcept;
        [[nodiscard]] static auto EqualIdentity(const std::string_view Left, const std::string_view Right) noexcept -> bool;
        [[nodiscard]] auto Find(const AcquireRequest& Request) const noexcept
            -> std::expected<Detail::CredentialIndexEntry, Failure>;
        std::shared_ptr<Detail::AccountStoreState> State_;
        std::size_t Ordinal_{0U};
    };
}
