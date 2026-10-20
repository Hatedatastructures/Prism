/**
 * @file ReloadCoordinator.hpp
 * @brief 只准备并验证配置 generation；运行时 ack 与唯一发布由 Application owner 完成。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Application/Configuration/GenerationBuilder.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Application::Configuration
{

    /** @brief parser 已拥有的候选配置及所有 generation 编译依赖。 */
    struct ReloadRequest final
    {
        Prism::GenerationId BaseGeneration{};
        PrismConfiguration Configuration{};
        std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> Builtins{};
        std::function<std::optional<std::string>(std::string_view)> SecretResolver{};
        Prism::Composition::Builtin::CapabilitySet AvailableCapabilities{};
    };

    class ReloadCoordinator final
    {
    public:
        using Result = std::expected<SharedConfigurationGeneration, ConfigurationError>;

        /** @brief 校验 current/base 后构造 owning candidate；该阶段绝不 ack 或发布。 */
        [[nodiscard]] auto Prepare(
            const SharedConfigurationGeneration &Current,
            ReloadRequest Request) const -> Result;
    };

} // namespace Prism::Application::Configuration
