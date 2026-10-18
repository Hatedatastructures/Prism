/** @file Materials.hpp
 * @brief 冷拥有的账户身份与各凭据域材料，完全不创建运行账本。
 */
#pragma once
#include <Prism/Account/Credential.hpp>
#include <Prism/Account/CredentialScope.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>

namespace Prism::Account
{
    /** @brief 单域秘密与已验证 wire identity；Scope 在冷装配冻结。 */
    struct CredentialMaterial final
    {
        CredentialScope Scope;
        std::string Identity;
        Prism::Account::Credential Credential;
    };
    /** @brief 材料独占秘密且只读，最后一个 Binding/lease/view 释放后擦除。 */
    class AccountMaterials final
    {
    public:
        struct CreateRequest final
        {
            Prism::AccountId AccountId;
            std::string DisplayIdentity;
            std::vector<CredentialMaterial> Credentials;
        };
        explicit AccountMaterials(CreateRequest Request)
            : AccountId_(Request.AccountId), DisplayIdentity_(std::move(Request.DisplayIdentity)),
              Credentials_(std::move(Request.Credentials))
        {
            if (!AccountId_ || Credentials_.empty()) { throw std::invalid_argument("invalid account materials"); }
            for (const auto& Entry : Credentials_)
            {
                if (!Entry.Scope || !Entry.Credential.IsValid()) { throw std::invalid_argument("invalid scoped credential"); }
            }
        }
        AccountMaterials(const AccountMaterials&) = delete;
        auto operator=(const AccountMaterials&) -> AccountMaterials& = delete;
        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId { return AccountId_; }
        [[nodiscard]] auto DisplayIdentity() const noexcept -> std::string_view { return DisplayIdentity_; }
        [[nodiscard]] auto Credentials() const noexcept -> const std::vector<CredentialMaterial>& { return Credentials_; }
        /** @brief 冷诊断只描述账户身份，不输出任何secret。 */
        [[nodiscard]] auto Redacted() const -> std::string { return std::to_string(AccountId_.Value()) + ":[redacted]"; }
    private:
        Prism::AccountId AccountId_;
        std::string DisplayIdentity_;
        std::vector<CredentialMaterial> Credentials_;
    };
}
