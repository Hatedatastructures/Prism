/** @file IdentityRegistry.hpp @brief 进程内账户身份注册和候选身份预留。 */
#pragma once

#include <Prism/Account/CredentialScope.hpp>
#include <Prism/Account/Store.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Application
{

    class AccountIdentityRegistry;

    /** @brief 单次配置准备的身份预留；提交移交映射，放弃只释放候选记录。 */
    class AccountIdentityPreparation final
    {
        using Failure = Prism::Fault::Failure;

    public:
        AccountIdentityPreparation(const AccountIdentityPreparation &) = delete;
        auto operator=(const AccountIdentityPreparation &) -> AccountIdentityPreparation & = delete;
        AccountIdentityPreparation(AccountIdentityPreparation &&) = delete;
        auto operator=(AccountIdentityPreparation &&) -> AccountIdentityPreparation & = delete;
        ~AccountIdentityPreparation();

        [[nodiscard]] auto Account(std::string_view Name)
            -> std::expected<Prism::AccountId, Failure>;

        [[nodiscard]] auto Scope(std::string_view ProtocolId)
            -> std::expected<Prism::Account::CredentialScope, Failure>;

        [[nodiscard]] auto Registry() const noexcept
            -> const std::shared_ptr<AccountIdentityRegistry> &
        {
            return Owner_;
        }

        /** @brief 冻结候选身份并校验稳定名称；失败回滚不会占正式名称或ID预算。 */
        auto StageCommit() noexcept -> std::expected<void, Failure>;

        /** @brief CAS 成功后无分配地提交候选名称映射并释放准备独占权。 */
        auto Commit() noexcept -> std::expected<void, Failure>;

    private:
        friend class AccountIdentityRegistry;
        explicit AccountIdentityPreparation(
            std::shared_ptr<AccountIdentityRegistry> OwnerValue) noexcept;
        auto Rollback() noexcept -> void;

        std::shared_ptr<AccountIdentityRegistry> Owner_;
        std::map<std::string, Prism::AccountId, std::less<>> CandidateAccounts_;
        std::map<std::string, Prism::Account::CredentialScope, std::less<>> CandidateScopes_;
        const std::uint64_t BaseNextAccount_;
        const std::uint32_t BaseNextScope_;
        bool Staged_{false};
        bool Completed_{false};
    };

    /**
     * @brief 控制面唯一拥有的稳定名称表和进程账户runtime owner。
     * @details 候选身份只保存在 preparation；失败/ValidateOnly 销毁时不占正式名称容量。
     */
    class AccountIdentityRegistry final : public std::enable_shared_from_this<AccountIdentityRegistry>
    {
        friend class AccountIdentityPreparation;

    public:
        static constexpr std::size_t MaxAccounts{4096U};
        static constexpr std::size_t MaxScopes{64U};

        AccountIdentityRegistry();

        [[nodiscard]] auto BeginPreparation()
            -> std::expected<std::shared_ptr<AccountIdentityPreparation>, Prism::Fault::Failure>;

        [[nodiscard]] auto RuntimeRegistry() const noexcept
            -> const std::shared_ptr<Prism::Account::AccountRuntimeRegistry> &
        {
            return RuntimeRegistry_;
        }

        [[nodiscard]] auto AccountCount() const noexcept -> std::size_t
        {
            return Accounts_.size();
        }

        [[nodiscard]] auto ScopeCount() const noexcept -> std::size_t
        {
            return Scopes_.size();
        }

    private:
        std::map<std::string, Prism::AccountId, std::less<>> Accounts_;
        std::map<std::string, Prism::Account::CredentialScope, std::less<>> Scopes_;
        std::shared_ptr<Prism::Account::AccountRuntimeRegistry> RuntimeRegistry_;
        std::atomic_flag Mutation_ = ATOMIC_FLAG_INIT;
        std::uint64_t NextAccount_{1U};
        std::uint32_t NextScope_{1U};
    };

} // namespace Prism::Application
