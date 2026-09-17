/**
 * @file GenerationBuilder.hpp
 * @brief Preview 配置 generation 构造器。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationGeneration.hpp>
#include <Preview/Application/Configuration/ConfigurationValidator.hpp>

#include <Preview/Account/SecureBytes.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

namespace Preview::Application::Configuration
{

    struct GenerationBuildOptions final
    {
        PreviewConfiguration Configuration{};
        std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> Builtins{};
        std::function<std::optional<std::string>(std::string_view)> SecretResolver{};
        Preview::Composition::Builtin::CapabilitySet AvailableCapabilities{};
        Preview::GenerationId Generation{};
    };

    using GenerationBuildRequest = GenerationBuildOptions;

    class GenerationBuilder final
    {
    public:
        using Result = std::expected<SharedConfigurationGeneration, ConfigurationError>;

        [[nodiscard]] static auto Build(GenerationBuildOptions Options) -> Result
        {
            auto Resolver = std::move(Options.SecretResolver);
            std::map<std::string, std::optional<Preview::Account::SecureBytes>> Resolved;
            const auto Resolve = [&Resolver, &Resolved](std::string_view Reference)
                -> std::optional<std::string>
            {
                auto [It, Inserted] = Resolved.try_emplace(std::string(Reference));
                if (Inserted && Resolver)
                {
                    std::optional<std::string> Value;
                    try
                    {
                        Value = Resolver(Reference);
                        if (Value && !Value->empty())
                        {
                            It->second.emplace(*Value);
                        }
                    }
                    catch (...)
                    {
                        It->second.reset();
                    }
                    if (Value)
                    {
                        std::fill(Value->begin(), Value->end(), '\0');
                        Value->clear();
                    }
                }
                if (!It->second || It->second->Size() == 0U)
                {
                    return std::nullopt;
                }
                const auto Value = It->second->View();
                return std::string(reinterpret_cast<const char *>(Value.data()), Value.size());
            };

            if (Options.Generation.Value() == 0U)
            {
                Options.Generation = Preview::GenerationId{1};
            }

            const auto Validation = ConfigurationValidator::Validate(ValidationRequest{
                Options.Configuration,
                ValidationOptions{
                    .Secrets = SecretRefResolver(SecretRefResolver::Callback(Resolve)),
                    .AvailableCapabilities = Options.AvailableCapabilities,
                    .Builtins = Options.Builtins,
                    .CheckSecrets = true,
                    .CheckCapabilities = true,
                    .RequireBuiltinSnapshot = true}});
            if (!Validation)
            {
                return std::unexpected(Validation.error());
            }

            auto Capabilities = Options.AvailableCapabilities;
            if (Options.Builtins)
            {
                Capabilities |= Options.Builtins->Capabilities();
            }

            auto SecretStore = std::make_shared<ResolvedSecrets>();
            const auto AddSecret = [&Resolved, &SecretStore](std::string_view Reference,
                                                               std::string_view Path)
                -> std::optional<ConfigurationError>
            {
                if (Reference.empty())
                {
                    return std::nullopt;
                }
                if (!SecretStore->Lookup(Reference).empty())
                {
                    return std::nullopt;
                }
                const auto It = Resolved.find(std::string(Reference));
                if (It == Resolved.end() || !It->second || It->second->Size() == 0U)
                {
                    return MakeConfigurationError(ConfigurationErrorCode::UnresolvedSecret,
                                                  std::string(Path),
                                                  "SecretRef cannot be resolved");
                }
                SecretStore->Add(std::string(Reference), std::move(*It->second));
                return std::nullopt;
            };

            for (std::size_t Index = 0; Index < Options.Configuration.Accounts.size(); ++Index)
            {
                const auto &Account = Options.Configuration.Accounts[Index];
                const auto Path = "Accounts[" + std::to_string(Index) + "].SecretRef";
                if (const auto Error = AddSecret(Account.SecretRef, Path); Error)
                {
                    return std::unexpected(*Error);
                }
            }

            for (std::size_t Index = 0; Index < Options.Configuration.Carriers.size(); ++Index)
            {
                const auto &Carrier = Options.Configuration.Carriers[Index];
                const auto Path = "Carriers[" + std::to_string(Index) + "].Options";
                const auto Error = std::visit(
                    [&AddSecret, &Path](const auto &TypedOptions)
                        -> std::optional<ConfigurationError>
                    {
                        using Option = std::remove_cvref_t<decltype(TypedOptions)>;
                        if constexpr (std::is_same_v<Option, RealityOptions>)
                        {
                            return AddSecret(TypedOptions.PrivateKeyRef,
                                             Path + ".PrivateKeyRef");
                        }
                        else if constexpr (std::is_same_v<Option, ShadowTlsOptions> ||
                                           std::is_same_v<Option, RestlsOptions>)
                        {
                            return AddSecret(TypedOptions.PasswordSecretRef,
                                             Path + ".PasswordSecretRef");
                        }
                        else if constexpr (std::is_same_v<Option, TrustTunnelOptions>)
                        {
                            if (const auto Error = AddSecret(
                                    TypedOptions.PrivateKeySecretRef,
                                    Path + ".PrivateKeySecretRef"); Error)
                            {
                                return Error;
                            }
                            return AddSecret(TypedOptions.PasswordSecretRef,
                                             Path + ".PasswordSecretRef");
                        }
                        else
                        {
                            return std::nullopt;
                        }
                    },
                    Carrier.Options);
                if (Error)
                {
                    return std::unexpected(*Error);
                }
            }

            for (std::size_t Index = 0; Index < Options.Configuration.Protocols.size(); ++Index)
            {
                const auto &Protocol = Options.Configuration.Protocols[Index];
                if (Protocol.Quic)
                {
                    if (const auto Error = AddSecret(
                            Protocol.Quic->CredentialSecretRef,
                            "Protocols[" + std::to_string(Index) + "].Quic.CredentialSecretRef");
                        Error)
                    {
                        return std::unexpected(*Error);
                    }
                }
            }

            return SharedConfigurationGeneration(new ConfigurationGeneration(
                ConfigurationGenerationData{
                    Options.Generation,
                    std::move(Options.Configuration),
                    Capabilities,
                    std::move(Options.Builtins),
                    std::move(SecretStore)}));
        }
    };

} // namespace Preview::Application::Configuration
