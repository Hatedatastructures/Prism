/**
 * @file AdmissionAuthority.hpp
 * @brief 账户 admission 与撤销对同一不可变运行时状态的中立视图。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Contract
{

    /** @brief 一次发布的账户成员与撤销事实；两组 ID 均有硬上限并按升序冻结。 */
    struct AccountAdmissionSnapshot final
    {
        static constexpr std::size_t MaxMembers{4096U};
        static constexpr std::size_t MaxRevocations{4096U};

        AccountAdmissionSnapshot(
            std::vector<Prism::AccountId> MemberValues,
            std::vector<Prism::AccountId> RevokedValues,
            const bool ClosedValue) noexcept
            : Members(std::move(MemberValues)),
              Revoked(std::move(RevokedValues)),
              Closed(ClosedValue)
        {
        }

        [[nodiscard]] auto IsMember(const Prism::AccountId Id) const noexcept -> bool
        {
            return Id && std::binary_search(Members.begin(), Members.end(), Id);
        }

        [[nodiscard]] auto IsRevoked(const Prism::AccountId Id) const noexcept -> bool
        {
            return Closed || !Id || std::binary_search(Revoked.begin(), Revoked.end(), Id);
        }

        [[nodiscard]] auto IsAdmitted(const Prism::AccountId Id) const noexcept -> bool
        {
            return IsMember(Id) && !IsRevoked(Id);
        }

        const std::vector<Prism::AccountId> Members;
        const std::vector<Prism::AccountId> Revoked;
        const bool Closed;
    };

    /** @brief admission 读预约的生命周期由 publication owner 计数。 */
    class AccountAdmissionLeaseOwner
    {
    public:
        virtual ~AccountAdmissionLeaseOwner() = default;
        virtual auto ReleaseAccountAdmission() noexcept -> void = 0;
    };

    /** @brief 无反向引用 publication 的预约计数 owner，避免snapshot/catalog/lease强环。 */
    class AccountAdmissionGate final : public AccountAdmissionLeaseOwner
    {
    public:
        [[nodiscard]] auto TryBeginAdmission() noexcept -> bool;

        [[nodiscard]] auto TryBeginPublication() noexcept -> bool;

        auto EndPublication() noexcept -> void;

        auto ReleaseAccountAdmission() noexcept -> void override;

    private:
        inline static constexpr std::uint64_t PublicationBit{std::uint64_t{1U} << 63U};
        std::atomic<std::uint64_t> State_{0U};
    };

    /** @brief 非阻塞 admission gate 的读预约；最终关闭者为它持有的 publication owner。 */
    class AccountAdmissionPermit final
    {
    public:
        AccountAdmissionPermit() = default;
        explicit AccountAdmissionPermit(
            std::shared_ptr<AccountAdmissionLeaseOwner> OwnerValue) noexcept;
        AccountAdmissionPermit(const AccountAdmissionPermit &) = delete;
        auto operator=(const AccountAdmissionPermit &) -> AccountAdmissionPermit & = delete;
        AccountAdmissionPermit(AccountAdmissionPermit &&Other) noexcept;
        auto operator=(AccountAdmissionPermit &&Other) noexcept -> AccountAdmissionPermit &;
        ~AccountAdmissionPermit() noexcept;

        [[nodiscard]] auto Active() const noexcept -> bool
        {
            return static_cast<bool>(Owner_);
        }

        auto Commit() noexcept -> void;

    private:
        auto Reset() noexcept -> void;

        std::shared_ptr<AccountAdmissionLeaseOwner> Owner_;
    };

    /** @brief 账户模块只依赖该 authority；运行时可投影同一 generation publication。 */
    class AccountAdmissionAuthority
    {
    public:
        using Snapshot = AccountAdmissionSnapshot;
        using SnapshotPin = std::shared_ptr<const Snapshot>;
        using Result = std::expected<void, Prism::Fault::Failure>;

        virtual ~AccountAdmissionAuthority() = default;
        [[nodiscard]] virtual auto Load() const noexcept -> SnapshotPin = 0;
        [[nodiscard]] virtual auto BeginAdmission(Prism::AccountId Id) noexcept
            -> std::expected<AccountAdmissionPermit, Prism::Fault::Failure> = 0;
        [[nodiscard]] virtual auto RevokeAccounts(
            std::span<const Prism::AccountId> Ids) noexcept -> Result = 0;
        [[nodiscard]] virtual auto CloseAllAccounts() noexcept -> Result = 0;
    };

} // namespace Prism::Contract
