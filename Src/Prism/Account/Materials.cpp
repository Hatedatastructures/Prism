/**
 * @file Materials.cpp
 * @brief 账户身份与凭据材料的冷验证实现。
 */
#include <Prism/Account/Materials.hpp>

#include <stdexcept>
#include <utility>

namespace Prism::Account
{
    AccountMaterials::AccountMaterials(CreateRequest Request)
        : AccountId_(Request.AccountId), DisplayIdentity_(std::move(Request.DisplayIdentity)),
          Credentials_(std::move(Request.Credentials))
    {
        if (!AccountId_ || Credentials_.empty()) { throw std::invalid_argument("invalid account materials"); }
        for (const auto& Entry : Credentials_)
        {
            if (!Entry.Scope || !Entry.Credential.IsValid()) { throw std::invalid_argument("invalid scoped credential"); }
        }
    }

    auto AccountMaterials::Redacted() const -> std::string
    {
        return std::to_string(AccountId_.Value()) + ":[redacted]";
    }
} // namespace Prism::Account
