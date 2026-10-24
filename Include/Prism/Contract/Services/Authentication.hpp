/** @file Authentication.hpp @brief 已解析 owning 账户服务与原 generation 的一致性合同。 */
#pragma once
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
namespace Prism::Contract
{
    /** @brief 凭据视图和认证器共享唯一 store snapshot；pin 与 Preparation 使用同一代次。 */
    struct AuthenticationServices final
    {
        Prism::Foundation::GenerationPin Generation;
        Prism::Account::CredentialIndexView Credentials;
        Prism::SharedAuthenticator Authenticator;
        [[nodiscard]] auto Matches(const Prism::Foundation::GenerationPin& Pin) const noexcept -> bool
        {
            return Pin && Generation && !Pin.owner_before(Generation) && !Generation.owner_before(Pin)
                && Pin->Id() == Generation->Id() && Pin->Id().Value() != 0;
        }
    };
}
