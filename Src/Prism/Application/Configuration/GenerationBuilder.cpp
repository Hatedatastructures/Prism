/** @file GenerationBuilder.cpp @brief Prism 配置 generation 构造实现。 */
#include <Prism/Application/Configuration/GenerationBuilder.hpp>
#include <Prism/Application/Configuration/Detail/PreparedConfigurationSecrets.hpp>

#include <memory>
#include <utility>

namespace Prism::Application::Configuration
{

    auto GenerationBuilder::Build(GenerationBuildOptions Options) -> Result
    {
        if (Options.Generation.Value() == 0U)
        {
            Options.Generation = Prism::GenerationId{1};
        }

        Detail::SensitiveStringMapWiper InlineWiper(Options.Configuration.Secrets);
        auto Resolution = std::unique_ptr<Detail::SecretResolutionTransaction>(
            new Detail::SecretResolutionTransaction(std::move(Options.Configuration.Secrets),
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

    auto GenerationBuilder::Build(PreparedGenerationBuildRequest Request) -> Result
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

    auto GenerationBuilder::ValidatePrepared(PreparedGenerationBuildRequest &Request,
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

    auto GenerationBuilder::BuildValidated(PreparedGenerationBuildRequest Request) -> Result
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
