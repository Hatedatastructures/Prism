/** @file Account.cpp @brief Prism 账户凭据和协议账户目录冷路径装配。 */

#include <Prism/Application/Assembly/Account.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Provider/Credential/Preparation.hpp>
#include <Prism/Foundation/ByteSpan.hpp>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Application::Assembly
{
    namespace
    {
        [[nodiscard]] auto ResolvedCredentialForProtocol(
            const Configuration::ConfigurationGeneration &Generation,
            const Configuration::AccountConfiguration &Configured,
            const Prism::Contract::ProtocolType Protocol)
            -> std::expected<std::string_view, StartupError>
        {
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Protocol);
            if (!Descriptor || Descriptor->AccountKey.empty())
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Accounts." + Configured.Id,
                    "protocol has no account credential material descriptor"));
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
            QuicCredentialMatcher(
                const Configuration::ConfigurationGeneration &Generation,
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
                    if (!Secret.empty() && Prism::ConstantTimeEqual(
                                               std::string_view(
                                                   reinterpret_cast<const char *>(Secret.data()),
                                                   Secret.size()),
                                               Target_.Value))
                    {
                        return true;
                    }
                }
                if (Prism::ConstantTimeEqual(Account.Credential, Target_.Value))
                {
                    return true;
                }
                if (const auto It = Account.Credentials.find(std::string(Target_.ProtocolBuiltin));
                    It != Account.Credentials.end() &&
                    Prism::ConstantTimeEqual(It->second, Target_.Value))
                {
                    return true;
                }
                return false;
            }

        private:
            const Configuration::ConfigurationGeneration &Generation_;
            ResolvedQuicCredentialTarget Target_;
        };

        struct ScopedProtocol final
        {
            const Prism::Contract::ProtocolConfiguration *Protocol;
            Prism::Account::CredentialScope Scope;
            std::optional<Prism::Contract::ProtocolType> Tcp;
            std::string_view QuicCredential;
            std::optional<std::size_t> QuicAccount;
        };

        /** @brief 按稳定组归属编译唯一额度、准入和流量策略。 */
        [[nodiscard]] auto CompileAccountPolicy(
            const Configuration::PrismConfiguration &ConfigurationValue,
            const Configuration::AccountConfiguration &Account)
            -> std::expected<Prism::Account::PolicySettings, StartupError>
        {
            Prism::Account::PolicyConfiguration Group;
            if (Account.GroupId)
            {
                const auto Found = std::find_if(
                    ConfigurationValue.AccountGroups.begin(),
                    ConfigurationValue.AccountGroups.end(),
                    [&Account](const auto &Value) { return Value.Id == *Account.GroupId; });
                if (Found == ConfigurationValue.AccountGroups.end())
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Accounts." + Account.Id + ".GroupId",
                        "账户组不存在"));
                }
                Group = Found->Policy;
            }
            const auto Compiled = Prism::Account::CompilePolicy(Account.Policy, Group);
            if (!Compiled)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Accounts." + Account.Id + ".Policy",
                    "账户有效策略无效"));
            }
            Prism::Account::PolicySettings Result;
            Result.Quota.MaxConnections = Compiled->Connections;
            Result.Quota.MaxStreams = Compiled->Streams;
            if (Compiled->AdmissionsPerSecond)
            {
                Result.Rate = Prism::Account::StrictGlobalRatePolicy{
                    *Compiled->AdmissionsPerSecond, 1000};
            }
            Result.Transfer = {
                Compiled->TrafficBytes,
                Compiled->UploadBytesPerSecond,
                Compiled->DownloadBytesPerSecond,
                Compiled->Cycle};
            return Result;
        }

        [[nodiscard]] auto CompileAccountScopes(const AccountPreparationRequest &Request)
            -> std::expected<std::vector<ScopedProtocol>, StartupError>
        {
            std::vector<ScopedProtocol> Result;
            const auto &ConfigurationValue = Request.Generation->Configuration();
            for (const auto &Protocol : ConfigurationValue.Protocols)
            {
                const auto Descriptor =
                    Prism::Composition::Protocol::ProtocolCatalog::Find(Protocol.Builtin);
                if (!Descriptor ||
                    Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        "Protocols." + Protocol.Id,
                        "protocol has no typed account material descriptor"));
                }
                const auto Scope = Request.IdentityPreparation->Scope(Protocol.Id);
                if (!Scope)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::Runtime,
                        "Protocols." + Protocol.Id,
                        "凭据域身份容量不足"));
                }
                ScopedProtocol Compiled{&Protocol, *Scope, {}, {}, {}};
                if (Protocol.Quic)
                {
                    if (!Descriptor->SupportsQuic)
                    {
                        return std::unexpected(Startup::MakeStartupError(
                            StartupErrorCode::UnsupportedService,
                            "Protocols." + Protocol.Id,
                            "non-QUIC protocol has QUIC credentials"));
                    }
                    const auto Secret =
                        Request.Generation->LookupSecret(Protocol.Quic->CredentialSecretRef);
                    if (Secret.empty())
                    {
                        return std::unexpected(Startup::MakeStartupError(
                            StartupErrorCode::Generation,
                            "Protocols." + Protocol.Id + ".Quic.CredentialSecretRef",
                            "缺少已解析QUIC凭据"));
                    }
                    Compiled.QuicCredential = {
                        reinterpret_cast<const char *>(Secret.data()), Secret.size()};
                    const QuicCredentialMatcher Matcher(
                        *Request.Generation,
                        {Compiled.QuicCredential,
                            Protocol.Quic->CredentialSecretRef,
                            Protocol.Builtin});
                    for (std::size_t Index = 0;
                         Index < ConfigurationValue.Accounts.size();
                         ++Index)
                    {
                        if (!Matcher.Matches(ConfigurationValue.Accounts[Index]))
                        {
                            continue;
                        }
                        if (Compiled.QuicAccount)
                        {
                            return std::unexpected(Startup::MakeStartupError(
                                StartupErrorCode::InvalidConfiguration,
                                "Protocols." + Protocol.Id,
                                "QUIC凭据属于多个账户"));
                        }
                        Compiled.QuicAccount = Index;
                    }
                    if (!Compiled.QuicAccount)
                    {
                        return std::unexpected(Startup::MakeStartupError(
                            StartupErrorCode::InvalidConfiguration,
                            "Protocols." + Protocol.Id,
                            "QUIC凭据没有所属账户"));
                    }
                }
                else if (Descriptor->SupportsTcp)
                {
                    Compiled.Tcp = Descriptor->Id;
                }
                else
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        "Protocols." + Protocol.Id,
                        "protocol requires its typed QUIC configuration"));
                }
                Result.push_back(Compiled);
            }
            return Result;
        }

        /** @brief 冷编译账户实例凭据，wire 解释只发生一次。 */
        [[nodiscard]] auto CompileAccountMaterials(
            const AccountPreparationRequest &Request,
            const std::vector<ScopedProtocol> &Protocols)
            -> std::expected<std::vector<Prism::Account::AccountDefinition>, StartupError>
        {
            std::vector<Prism::Account::AccountDefinition> Definitions;
            const auto &Accounts = Request.Generation->Configuration().Accounts;
            for (std::size_t Index = 0; Index < Accounts.size(); ++Index)
            {
                const auto &Configured = Accounts[Index];
                const auto Id = Request.IdentityPreparation->Account(Configured.Id);
                if (!Id)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::Runtime,
                        "Accounts." + Configured.Id,
                        "账户身份容量不足"));
                }
                std::vector<Prism::Account::CredentialMaterial> Materials;
                for (const auto &Protocol : Protocols)
                {
                    if (Protocol.Protocol->Quic)
                    {
                        if (Protocol.QuicAccount != Index)
                        {
                            continue;
                        }
                        Materials.push_back({
                            Protocol.Scope,
                            {},
                            Prism::Account::Credential::Token(Protocol.QuicCredential)});
                        continue;
                    }
                    const auto Resolved = ResolvedCredentialForProtocol(
                        *Request.Generation, Configured, *Protocol.Tcp);
                    if (!Resolved)
                    {
                        return std::unexpected(Resolved.error());
                    }
                    auto Credential = Prism::Composition::Provider::ProtocolCredentialPreparation::Prepare(
                        *Protocol.Tcp, *Resolved);
                    if (!Credential)
                    {
                        return std::unexpected(Startup::MakeStartupError(
                            StartupErrorCode::InvalidConfiguration,
                            "Accounts." + Configured.Id + ".Credential",
                            "protocol credential material is invalid"));
                    }
                    std::string Identity;
                    if (Credential->Kind() == Prism::Account::CredentialKind::Password)
                    {
                        Identity = Configured.Id;
                    }
                    Materials.push_back({
                        Protocol.Scope, std::move(Identity), std::move(*Credential)});
                }
                if (Materials.empty())
                {
                    continue;
                }
                auto Material = std::make_shared<const Prism::Account::AccountMaterials>(
                    Prism::Account::AccountMaterials::CreateRequest{
                        *Id, Configured.Id, std::move(Materials)});
                const auto Policy = CompileAccountPolicy(
                    Request.Generation->Configuration(), Configured);
                if (!Policy)
                {
                    return std::unexpected(Policy.error());
                }
                Definitions.push_back({std::move(Material), *Policy});
            }
            return Definitions;
        }
    } // namespace

    auto PrepareAccountCatalog(AccountPreparationRequest Request)
        -> std::expected<PreparedAccountCatalog, StartupError>
    {
        if (!Request.Generation || !Request.Store || !Request.IdentityPreparation ||
            !Request.IdentityPreparation->Registry())
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime,
                "Accounts",
                "账户装配缺少真实owner"));
        }
        const auto Scopes = CompileAccountScopes(Request);
        if (!Scopes)
        {
            return std::unexpected(Scopes.error());
        }
        PreparedAccountCatalog Result;
        Result.Catalog.Store = Request.Store;
        Result.Catalog.Identities = Request.IdentityPreparation->Registry();
        Result.Catalog.IdentityPreparation = Request.IdentityPreparation;
        for (const auto &Scope : *Scopes)
        {
            auto View = Request.Store->CompileScope(Scope.Scope);
            if (!View)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Runtime,
                    "Protocols." + Scope.Protocol->Id,
                    "无法编译凭据域"));
            }
            auto Authenticator = std::make_shared<Prism::DirectoryAuthenticator>(*View);
            Result.Catalog.Protocols.emplace(
                Scope.Protocol->Id,
                Prism::Contract::AuthenticationServices{
                    Request.Generation, std::move(*View), std::move(Authenticator)});
        }
        auto Definitions = CompileAccountMaterials(Request, *Scopes);
        if (!Definitions)
        {
            return std::unexpected(Definitions.error());
        }
        auto Update = Request.Store->PrepareReplacement(*Definitions);
        if (!Update)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime,
                "Accounts",
                "无法准备完整账户发布"));
        }
        Result.Update = std::move(*Update);
        return Result;
    }

} // namespace Prism::Application::Assembly
