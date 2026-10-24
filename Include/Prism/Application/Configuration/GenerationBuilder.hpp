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


} // namespace Prism::Application::Configuration
