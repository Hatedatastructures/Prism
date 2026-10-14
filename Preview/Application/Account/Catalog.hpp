/** @file Catalog.hpp @brief 冷编译的协议实例凭据域和进程唯一账户store装配值。 */
#pragma once
#include <Preview/Application/Account/IdentityRegistry.hpp>
#include <Preview/Account/Store.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <map>
#include <memory>
#include <string>
#include <string_view>
namespace Preview::Application
{
    /** @brief 每个Protocol.Id独立凭据域，全部服务共同pin一份process store。 */
    struct AccountCatalog final
    {
        std::shared_ptr<Preview::Account::AccountStore> Store;
        std::shared_ptr<AccountIdentityRegistry> Identities;
        /** @brief 未发布配置的身份预留；只在GenerationPublication CAS成功后提交。 */
        std::shared_ptr<AccountIdentityPreparation> IdentityPreparation;
        std::map<std::string, Preview::Contract::AuthenticationServices, std::less<>> Protocols;
        /** @brief 只在配置/启动冷路径按名字绑定；运行时消费冻结的service值。 */
        [[nodiscard]] auto Find(std::string_view ProtocolId) const noexcept
            -> const Preview::Contract::AuthenticationServices*
        {
            const auto It = Protocols.find(ProtocolId);
            if (It == Protocols.end()) return nullptr;
            return &It->second;
        }
    };
}
