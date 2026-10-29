/** @file Account.hpp @brief Prism 账户凭据和协议账户目录装配契约。 */
#pragma once

#include <Prism/Application/AccountCatalog.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Application/Definition.hpp>

#include <expected>
#include <memory>

namespace Prism::Application::Assembly
{

    namespace Configuration = Prism::Application::Configuration;

    /** @brief 配置准备输入真实拥有 generation、唯一 store 与进程身份注册器。 */
    struct AccountPreparationRequest final
    {
        Configuration::SharedConfigurationGeneration Generation;
        std::shared_ptr<Prism::Account::AccountStore> Store;
        std::shared_ptr<AccountIdentityPreparation> IdentityPreparation;
    };

    /** @brief 一次发布前的完整账户材料与实例 scope。 */
    struct PreparedAccountCatalog final
    {
        AccountCatalog Catalog;
        Prism::Account::PreparedAccountUpdate Update;
    };

    /**
     * @brief 从完整配置准备唯一账户发布，不构造每协议目录或每 QUIC 账本。
     * @details 只在控制线程冷路径调用；结果持有真实 store、材料和提交令牌，失败不会部分发布。
     */
    [[nodiscard]] auto PrepareAccountCatalog(AccountPreparationRequest Request)
        -> std::expected<PreparedAccountCatalog, StartupError>;

} // namespace Prism::Application::Assembly
