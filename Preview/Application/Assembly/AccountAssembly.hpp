/**
 * @file AccountAssembly.hpp
 * @brief Preview 账户凭据和协议账户目录的冷路径装配。
 * @details 该 owner 只把已解析 generation 转成 typed account records、
 *          protocol authenticator 和 QUIC credential context；不启动 listener，
 *          不持有协议会话，也不参与 Application rollback。
 */

#pragma once

#include <Preview/Account/Account.hpp>
#include <Preview/Application/Account/Catalog.hpp>
#include <Preview/Application/Application.hpp>
#include <Preview/Application/Configuration/Configuration.hpp>
#include <Preview/Application/Startup/StartupErrors.hpp>
#include <Preview/Composition/Protocol/ProtocolCatalog.hpp>
#include <Preview/Composition/Provider/ProviderCatalog.hpp>
#include <Preview/Composition/Provider/ProtocolCredentialPreparation.hpp>
#include <Preview/Foundation/ByteSpan.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Preview::Application::Assembly
{

    namespace Configuration = Preview::Application::Configuration;

    [[nodiscard]] inline auto ResolvedCredentialForProtocol(
        const Configuration::ConfigurationGeneration &Generation,
        const Configuration::AccountConfiguration &Configured,
        const Preview::Contract::ProtocolType Protocol) -> std::expected<std::string_view, StartupError>
    {
        const auto Descriptor=Preview::Composition::Protocol::ProtocolCatalog::Find(Protocol);
        if(!Descriptor || Descriptor->AccountKey.empty())
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                "Accounts."+Configured.Id,"protocol has no account credential material descriptor"));
        }
        if (const auto It = Configured.Credentials.find(std::string(Descriptor->AccountKey));
            It != Configured.Credentials.end())
        {
            return It->second;
        }
        if (Configured.SecretRef.empty())
        {
            return Configured.Credential;
        }
        const auto Secret = Generation.LookupSecret(Configured.SecretRef);
        if (Secret.empty())
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Generation,
                "Accounts." + Configured.Id + ".SecretRef",
                "configuration generation does not contain the resolved secret"));
        }
        return std::string_view(reinterpret_cast<const char *>(Secret.data()), Secret.size());
    }

    struct ResolvedQuicCredentialTarget final
    {
        std::string_view Value;
        std::string_view SecretRef;
        std::string_view ProtocolBuiltin;
    };

    class QuicCredentialMatcher final
    {
    public:
        QuicCredentialMatcher(const Configuration::ConfigurationGeneration &Generation,
            ResolvedQuicCredentialTarget Target)
            : Generation_(Generation), Target_(Target)
        {
        }

        [[nodiscard]] auto Matches(const Configuration::AccountConfiguration &Account) const -> bool
        {
            if (!Target_.SecretRef.empty() && Account.SecretRef == Target_.SecretRef)
            {
                return true;
            }
            if (!Account.SecretRef.empty())
            {
                const auto Secret = Generation_.LookupSecret(Account.SecretRef);
                if (!Secret.empty() && Preview::ConstantTimeEqual(
                                           std::string_view(
                                               reinterpret_cast<const char *>(Secret.data()),
                                               Secret.size()),
                                           Target_.Value))
                {
                    return true;
                }
            }
            if (Preview::ConstantTimeEqual(Account.Credential, Target_.Value))
            {
                return true;
            }
            if (const auto It = Account.Credentials.find(std::string(Target_.ProtocolBuiltin));
                It != Account.Credentials.end() &&
                Preview::ConstantTimeEqual(It->second, Target_.Value))
            {
                return true;
            }
            return false;
        }

    private:
        const Configuration::ConfigurationGeneration& Generation_;
        ResolvedQuicCredentialTarget Target_;
    };

    /** @brief 配置准备输入真实拥有generation、唯一store与进程身份注册器。 */
    struct AccountPreparationRequest final
    {
        Configuration::SharedConfigurationGeneration Generation;
        std::shared_ptr<Preview::Account::AccountStore> Store;
        std::shared_ptr<AccountIdentityPreparation> IdentityPreparation;
    };
    /** @brief 一次发布前的完整材料与实例scope；令牌未Commit时不改变认证事实。 */
    struct PreparedAccountCatalog final
    {
        AccountCatalog Catalog;
        Preview::Account::PreparedAccountUpdate Update;
    };
    struct ScopedProtocol final
    {
        const Preview::Contract::ProtocolConfiguration* Protocol;
        Preview::Account::CredentialScope Scope;
        std::optional<Preview::Contract::ProtocolType> Tcp;
        std::string_view QuicCredential;
        std::optional<std::size_t> QuicAccount;
    };
    [[nodiscard]] inline auto CompileAccountScopes(const AccountPreparationRequest& Request)
        -> std::expected<std::vector<ScopedProtocol>, StartupError>
    {
        std::vector<ScopedProtocol> Result;
        const auto& Configuration = Request.Generation->Configuration();
        for (const auto& Protocol : Configuration.Protocols)
        {
            const auto Descriptor=Preview::Composition::Protocol::ProtocolCatalog::Find(Protocol.Builtin);
            if(!Descriptor || Descriptor->Kind!=Preview::Composition::Protocol::DescriptorKind::Protocol)
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::UnsupportedService,
                    "Protocols."+Protocol.Id,"protocol has no typed account material descriptor"));
            const auto Scope = Request.IdentityPreparation->Scope(Protocol.Id);
            if (!Scope) return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
                "Protocols." + Protocol.Id, "凭据域身份容量不足"));
            ScopedProtocol Compiled{&Protocol,*Scope,{}, {}, {}};
            if (Protocol.Quic)
            {
                if(!Descriptor->SupportsQuic)return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::UnsupportedService,"Protocols."+Protocol.Id,"non-QUIC protocol has QUIC credentials"));
                const auto Secret = Request.Generation->LookupSecret(Protocol.Quic->CredentialSecretRef);
                if (Secret.empty()) return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Generation,
                    "Protocols." + Protocol.Id + ".Quic.CredentialSecretRef", "缺少已解析QUIC凭据"));
                Compiled.QuicCredential = {reinterpret_cast<const char*>(Secret.data()), Secret.size()};
                const QuicCredentialMatcher Matcher(*Request.Generation, {Compiled.QuicCredential,
                    Protocol.Quic->CredentialSecretRef, Protocol.Builtin});
                for (std::size_t Index = 0; Index < Configuration.Accounts.size(); ++Index)
                {
                    if (!Matcher.Matches(Configuration.Accounts[Index])) continue;
                    if (Compiled.QuicAccount) return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::InvalidConfiguration, "Protocols." + Protocol.Id, "QUIC凭据属于多个账户"));
                    Compiled.QuicAccount = Index;
                }
                if (!Compiled.QuicAccount) return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::InvalidConfiguration, "Protocols." + Protocol.Id, "QUIC凭据没有所属账户"));
            }
            else if(Descriptor->SupportsTcp)Compiled.Tcp=Descriptor->Id;
            else return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::UnsupportedService,"Protocols."+Protocol.Id,"protocol requires its typed QUIC configuration"));
            Result.push_back(Compiled);
        }
        return Result;
    }
    /** @brief 冷编译一名账户所有实例凭据，UUID/PSK/Token wire解释只发生一次。 */
    [[nodiscard]] inline auto CompileAccountMaterials(const AccountPreparationRequest& Request,
        const std::vector<ScopedProtocol>& Protocols)
        -> std::expected<std::vector<Preview::Account::AccountDefinition>, StartupError>
    {
        std::vector<Preview::Account::AccountDefinition> Definitions;
        const auto& Accounts = Request.Generation->Configuration().Accounts;
        for (std::size_t Index = 0; Index < Accounts.size(); ++Index)
        {
            const auto& Configured = Accounts[Index];
            const auto Id = Request.IdentityPreparation->Account(Configured.Id);
            if (!Id) return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
                "Accounts." + Configured.Id, "账户身份容量不足"));
            std::vector<Preview::Account::CredentialMaterial> Materials;
            for (const auto& Protocol : Protocols)
            {
                if (Protocol.Protocol->Quic)
                {
                    if (Protocol.QuicAccount != Index) continue;
                    Materials.push_back({Protocol.Scope, {}, Preview::Account::Credential::Token(Protocol.QuicCredential)});
                    continue;
                }
                const auto Resolved = ResolvedCredentialForProtocol(*Request.Generation, Configured, *Protocol.Tcp);
                if (!Resolved) return std::unexpected(Resolved.error());
                auto Credential=Preview::Composition::Provider::ProtocolCredentialPreparation::Prepare(
                    *Protocol.Tcp,*Resolved);
                if(!Credential)return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,"Accounts."+Configured.Id+".Credential",
                    "protocol credential material is invalid"));
                std::string Identity;
                if (Credential->Kind() == Preview::Account::CredentialKind::Password) Identity = Configured.Id;
                Materials.push_back({Protocol.Scope, std::move(Identity), std::move(*Credential)});
            }
            if (Materials.empty()) continue;
            auto Material = std::make_shared<const Preview::Account::AccountMaterials>(
                Preview::Account::AccountMaterials::CreateRequest{*Id, Configured.Id, std::move(Materials)});
            Definitions.push_back({std::move(Material), {}});
        }
        return Definitions;
    }
    /**
     * @brief 从完整配置准备唯一账户发布，不再构造每协议目录或每QUIC账本。
     * @details 仅在控制线程冷路径调用；结果pins真实store/材料/token，发布失败不部分修改。
     */
    [[nodiscard]] inline auto PrepareAccountCatalog(AccountPreparationRequest Request)
        -> std::expected<PreparedAccountCatalog, StartupError>
    {
        if (!Request.Generation || !Request.Store || !Request.IdentityPreparation ||
            !Request.IdentityPreparation->Registry())
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime, "Accounts", "账户装配缺少真实owner"));
        const auto Scopes = CompileAccountScopes(Request);
        if (!Scopes) return std::unexpected(Scopes.error());
        PreparedAccountCatalog Result;
        Result.Catalog.Store = Request.Store;
        Result.Catalog.Identities = Request.IdentityPreparation->Registry();
        Result.Catalog.IdentityPreparation = Request.IdentityPreparation;
        for (const auto& Scope : *Scopes)
        {
            auto View = Request.Store->CompileScope(Scope.Scope);
            if (!View) return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
                "Protocols." + Scope.Protocol->Id, "无法编译凭据域"));
            auto Authenticator = std::make_shared<Preview::DirectoryAuthenticator>(*View);
            Result.Catalog.Protocols.emplace(Scope.Protocol->Id,
                Preview::Contract::AuthenticationServices{Request.Generation, std::move(*View), std::move(Authenticator)});
        }
        auto Definitions = CompileAccountMaterials(Request, *Scopes);
        if (!Definitions) return std::unexpected(Definitions.error());
        auto Update = Request.Store->PrepareReplacement(*Definitions);
        if (!Update) return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime,
            "Accounts", "无法准备完整账户发布"));
        Result.Update = std::move(*Update);
        return Result;
    }
} // namespace Preview::Application::Assembly
