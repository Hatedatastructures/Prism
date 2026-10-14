/**
 * @file ReloadCoordinator.hpp
 * @brief 只准备并验证配置 generation；运行时 ack 与唯一发布由 Application owner 完成。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationError.hpp>
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

namespace Preview::Application::Configuration
{

    /** @brief parser 已拥有的候选配置及所有 generation 编译依赖。 */
    struct ReloadRequest final
    {
        Preview::GenerationId BaseGeneration{};
        PreviewConfiguration Configuration{};
        std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> Builtins{};
        std::function<std::optional<std::string>(std::string_view)> SecretResolver{};
        Preview::Composition::Builtin::CapabilitySet AvailableCapabilities{};
    };

    class ReloadCoordinator final
    {
    public:
        using Result = std::expected<SharedConfigurationGeneration, ConfigurationError>;

        /** @brief 校验 current/base 后构造 owning candidate；该阶段绝不 ack 或发布。 */
        [[nodiscard]] auto Prepare(
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
            Options.Generation = Preview::GenerationId{CurrentValue + 1U};
            return GenerationBuilder::Build(std::move(Options));
        }
    };

} // namespace Preview::Application::Configuration
