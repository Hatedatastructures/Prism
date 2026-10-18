/**
 * @file GenerationBuilder.hpp
 * @brief Prism 配置 generation 构造器接口。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationGeneration.hpp>
#include <Prism/Application/Configuration/ConfigurationValidator.hpp>
#include <Prism/Application/Configuration/PreparedConfiguration.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Application::Configuration
{

    struct GenerationBuildOptions final
    {
        PrismConfiguration Configuration{};
        std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> Builtins{};
        std::function<std::optional<std::string>(std::string_view)> SecretResolver{};
        Prism::Composition::Builtin::CapabilitySet AvailableCapabilities{};
        Prism::GenerationId Generation{};
    };

    using GenerationBuildRequest = GenerationBuildOptions;

    struct PreparedGenerationBuildRequest final
    {
        PreparedConfiguration Prepared;
        std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> Builtins{};
        Prism::Composition::Builtin::CapabilitySet AvailableCapabilities{};
        Prism::GenerationId Generation{};
    };

    class GenerationBuilder final
    {
    public:
        using Result = std::expected<SharedConfigurationGeneration, ConfigurationError>;
        using SecretLookup = std::function<ResolvedSecrets::View(std::string_view)>;

        [[nodiscard]] static auto Build(GenerationBuildOptions Options) -> Result;
        [[nodiscard]] static auto Build(PreparedGenerationBuildRequest Request) -> Result;

    private:
        [[nodiscard]] static auto ValidatePrepared(PreparedGenerationBuildRequest &Request,
                                                   SecretLookup Lookup)
            -> ConfigurationValidator::Result;
        [[nodiscard]] static auto BuildValidated(PreparedGenerationBuildRequest Request) -> Result;
    };


    inline auto GenerationBuilder::Build(GenerationBuildOptions Options) -> Result
    {
        if (Options.Generation.Value() == 0U)
        {
            Options.Generation = Prism::GenerationId{1};
        }

        Detail::SensitiveStringMapWiper InlineWiper(Options.Configuration.Secrets);
        auto Resolution = std::unique_ptr<SecretResolutionTransaction>(
            new SecretResolutionTransaction(std::move(Options.Configuration.Secrets),
                                            std::move(Options.SecretResolver)));
        PreparedConfiguration Prepared{
            std::move(Options.Configuration), std::move(Resolution)};
        PreparedGenerationBuildRequest Request{
            std::move(Prepared),
            std::move(Options.Builtins),
            Options.AvailableCapabilities,
            Options.Generation};

        const auto Validation = ValidatePrepared(
            Request,
            [&Request](const std::string_view Reference)
            { return Request.Prepared.Resolution().Resolve(Reference); });
        if (!Validation)
        {
            return std::unexpected(Validation.error());
        }
        Request.Prepared.Resolution().Seal();
        return BuildValidated(std::move(Request));
    }

    inline auto GenerationBuilder::Build(PreparedGenerationBuildRequest Request) -> Result
    {
        if (Request.Generation.Value() == 0U)
        {
            Request.Generation = Prism::GenerationId{1};
        }

        const auto Validation = ValidatePrepared(
            Request,
            [&Request](const std::string_view Reference)
            { return Request.Prepared.Resolution().Lookup(Reference); });
        if (!Validation)
        {
            return std::unexpected(Validation.error());
        }
        return BuildValidated(std::move(Request));
    }

    inline auto GenerationBuilder::ValidatePrepared(PreparedGenerationBuildRequest &Request,
                                             SecretLookup Lookup)
        -> ConfigurationValidator::Result
    {
        return ConfigurationValidator::Validate(ValidationRequest{
            Request.Prepared.Configuration(),
            ValidationOptions{
                .SecretLookup = std::move(Lookup),
                .AvailableCapabilities = Request.AvailableCapabilities,
                .Builtins = Request.Builtins,
                .CheckSecrets = true,
                .CheckCapabilities = true,
                .RequireBuiltinSnapshot = true}});
    }

    inline auto GenerationBuilder::BuildValidated(PreparedGenerationBuildRequest Request) -> Result
    {
        auto Capabilities = Request.AvailableCapabilities;
        if (Request.Builtins)
        {
            Capabilities |= Request.Builtins->Capabilities();
        }

        auto UniqueSecrets = std::move(Request.Prepared).TakeResolvedSecrets();
        std::shared_ptr<const ResolvedSecrets> SecretStore{std::move(UniqueSecrets)};
        auto Configuration = std::move(Request.Prepared).TakeConfiguration();
        return SharedConfigurationGeneration(new ConfigurationGeneration(
            ConfigurationGenerationData{
                Request.Generation,
                std::move(Configuration),
                Capabilities,
                std::move(Request.Builtins),
                std::move(SecretStore)}));
    }

} // namespace Prism::Application::Configuration
