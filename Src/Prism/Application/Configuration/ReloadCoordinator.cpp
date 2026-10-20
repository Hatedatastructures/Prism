/** @file ReloadCoordinator.cpp @brief Prism 配置热重载候选 generation 准备实现。 */
#include <Prism/Application/Configuration/ReloadCoordinator.hpp>

#include <limits>
#include <utility>

namespace Prism::Application::Configuration
{

    auto ReloadCoordinator::Prepare(
        const SharedConfigurationGeneration &Current,
        ReloadRequest Request) const -> Result
    {
        if (!Current || !Current->Id() || Request.BaseGeneration != Current->Id())
        {
            return std::unexpected(MakeConfigurationError(
                ConfigurationErrorCode::PublishConflict,
                "BaseGeneration",
                "base generation does not match the active generation"));
        }
        if (!Current->Configuration().HotReload.Enabled)
        {
            return std::unexpected(MakeConfigurationError(
                ConfigurationErrorCode::HotReloadDisabled,
                "HotReload.Enabled",
                "hot reload is disabled for the active generation"));
        }
        const auto CurrentValue = Current->Id().Value();
        if (CurrentValue == std::numeric_limits<std::uint64_t>::max())
        {
            return std::unexpected(MakeConfigurationError(
                ConfigurationErrorCode::InvalidGeneration,
                "Generation.Id",
                "generation id cannot be advanced"));
        }
        GenerationBuildOptions Options;
        Options.Configuration = std::move(Request.Configuration);
        Options.Builtins = std::move(Request.Builtins);
        Options.SecretResolver = std::move(Request.SecretResolver);
        Options.AvailableCapabilities = Request.AvailableCapabilities;
        Options.Generation = Prism::GenerationId{CurrentValue + 1U};
        return GenerationBuilder::Build(std::move(Options));
    }

} // namespace Prism::Application::Configuration
