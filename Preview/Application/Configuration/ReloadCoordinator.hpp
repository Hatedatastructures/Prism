/**
 * @file ReloadCoordinator.hpp
 * @brief Preview 配置 generation 的确认和原子发布协调器。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationStore.hpp>
#include <Preview/Application/Configuration/GenerationBuilder.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Application::Configuration
{

    using WorkerAcknowledgement = std::function<bool(const ConfigurationGeneration &)>;

    struct ReloadRequest final
    {
        PreviewConfiguration Configuration{};
        std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> Builtins{};
        std::function<std::optional<std::string>(std::string_view)> SecretResolver{};
        Preview::Composition::Builtin::CapabilitySet AvailableCapabilities{};
        std::vector<WorkerAcknowledgement> Workers;
    };

    class ReloadCoordinator final
    {
    public:
        explicit ReloadCoordinator(ConfigurationStore &Store) : Store_(Store) {}

        [[nodiscard]] auto Reload(ReloadRequest Request)
            -> std::expected<SharedConfigurationGeneration, ConfigurationError>
        {
            if (!Request.Configuration.HotReload.Enabled)
            {
                return std::unexpected(MakeConfigurationError(
                    ConfigurationErrorCode::HotReloadDisabled,
                    "HotReload.Enabled",
                    "hot reload is disabled"));
            }

            const auto Current = Store_.Current();
            const auto CurrentValue = Current ? Current->Id().Value() : std::uint64_t{0};
            if (CurrentValue == std::numeric_limits<std::uint64_t>::max())
            {
                return std::unexpected(MakeConfigurationError(
                    ConfigurationErrorCode::InvalidGeneration,
                    "Generation.Id",
                    "generation id cannot be advanced"));
            }

            GenerationBuildOptions BuildOptions;
            BuildOptions.Configuration = std::move(Request.Configuration);
            BuildOptions.Builtins = std::move(Request.Builtins);
            BuildOptions.SecretResolver = std::move(Request.SecretResolver);
            BuildOptions.AvailableCapabilities = Request.AvailableCapabilities;
            BuildOptions.Generation = Preview::GenerationId{CurrentValue + 1U};
            const auto Candidate = GenerationBuilder::Build(std::move(BuildOptions));
            if (!Candidate)
            {
                return std::unexpected(Candidate.error());
            }

            if (Request.Workers.empty())
            {
                return std::unexpected(MakeConfigurationError(
                    ConfigurationErrorCode::MissingAcknowledgement,
                    "Workers",
                    "at least one worker acknowledgement is required"));
            }

            for (const auto &Worker : Request.Workers)
            {
                if (!Worker)
                {
                    return std::unexpected(MakeConfigurationError(
                        ConfigurationErrorCode::WorkerRejected,
                        "Workers",
                        "worker acknowledgement callback is empty"));
                }
                try
                {
                    if (!Worker(**Candidate))
                    {
                        return std::unexpected(MakeConfigurationError(
                            ConfigurationErrorCode::WorkerRejected,
                            "Workers",
                            "worker rejected the candidate generation"));
                    }
                }
                catch (...)
                {
                    return std::unexpected(MakeConfigurationError(
                        ConfigurationErrorCode::WorkerRejected,
                        "Workers",
                        "worker acknowledgement threw an exception"));
                }
            }

            if (const auto Published = Store_.Publish(*Candidate); !Published)
            {
                return std::unexpected(Published.error());
            }
            return *Candidate;
        }

    private:
        ConfigurationStore &Store_;
    };

} // namespace Preview::Application::Configuration
