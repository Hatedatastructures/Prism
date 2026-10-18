/**
 * @file ValidationTypes.hpp
 * @brief 配置校验请求的公共值类型。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Application/Configuration/ResolvedSecrets.hpp>
#include <Prism/Application/Configuration/SecretRefResolver.hpp>
#include <Prism/Composition/Builtin/Snapshot.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <string_view>

namespace Prism::Application::Configuration
{

    using ValidationResult = std::expected<void, ConfigurationError>;

    /** @brief 配置校验阶段需要的外部能力和密钥解析输入。 */
    struct ValidationOptions final
    {
        SecretRefResolver Secrets{};
        std::function<ResolvedSecrets::View(std::string_view)> SecretLookup{};
        Prism::Composition::Builtin::CapabilitySet AvailableCapabilities{};
        std::shared_ptr<const Prism::Composition::Builtin::BuiltinSnapshot> Builtins{};
        bool CheckSecrets{true};
        bool CheckCapabilities{true};
        bool RequireBuiltinSnapshot{false};
    };

    /** @brief 校验请求借用配置对象并拥有本次校验所需选项。 */
    struct ValidationRequest final
    {
        const PrismConfiguration &Configuration;
        ValidationOptions Options{};
    };

} // namespace Prism::Application::Configuration
