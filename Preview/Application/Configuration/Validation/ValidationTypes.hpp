/**
 * @file ValidationTypes.hpp
 * @brief 配置校验请求的公共值类型。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationError.hpp>
#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Application/Configuration/ResolvedSecrets.hpp>
#include <Preview/Application/Configuration/SecretRefResolver.hpp>
#include <Preview/Composition/Builtin/Snapshot.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <string_view>

namespace Preview::Application::Configuration
{

    using ValidationResult = std::expected<void, ConfigurationError>;

    /** @brief 配置校验阶段需要的外部能力和密钥解析输入。 */
    struct ValidationOptions final
    {
        SecretRefResolver Secrets{};
        std::function<ResolvedSecrets::View(std::string_view)> SecretLookup{};
        Preview::Composition::Builtin::CapabilitySet AvailableCapabilities{};
        std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> Builtins{};
        bool CheckSecrets{true};
        bool CheckCapabilities{true};
        bool RequireBuiltinSnapshot{false};
    };

    /** @brief 校验请求借用配置对象并拥有本次校验所需选项。 */
    struct ValidationRequest final
    {
        const PreviewConfiguration &Configuration;
        ValidationOptions Options{};
    };

} // namespace Preview::Application::Configuration
