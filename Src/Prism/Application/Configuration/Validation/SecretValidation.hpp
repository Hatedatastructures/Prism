/**
 * @file SecretValidation.hpp
 * @brief SecretRef 字段和解析结果校验。
 */
#pragma once

#include <Prism/Application/Configuration/PreparedConfiguration.hpp>
#include <Prism/Application/Configuration/Detail/PreparedConfigurationSecrets.hpp>
#include <Prism/Application/Configuration/Validation/CommonValidation.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace Prism::Application::Configuration::Validation
{

    [[nodiscard]] inline auto ValidateSecretReference(const std::string &Reference,
                                                      const std::string &Path,
                                                      const ValidationOptions &Options) -> Result
    {
        if (const auto ResultValue = RequireText(Reference, Path, "SecretRef is required"); !ResultValue)
        {
            return ResultValue;
        }
        if (!Options.CheckSecrets)
        {
            return {};
        }

        if (Options.SecretLookup)
        {
            ResolvedSecrets::View Secret;
            try
            {
                Secret = Options.SecretLookup(Reference);
            }
            catch (...)
            {
                Secret = {};
            }
            if (Secret.empty())
            {
                return Failure(ConfigurationErrorCode::UnresolvedSecret,
                               Path,
                               "SecretRef cannot be resolved");
            }
            return {};
        }

        std::optional<std::string> Secret;
        try
        {
            Secret = Options.Secrets.Resolve(Reference);
        }
        catch (...)
        {
            Secret.reset();
        }
        if (!Secret)
        {
            return Failure(ConfigurationErrorCode::UnresolvedSecret,
                           Path,
                           "SecretRef cannot be resolved");
        }
        Detail::SensitiveStringWiper Wiper(*Secret);
        if (Secret->empty())
        {
            return Failure(ConfigurationErrorCode::UnresolvedSecret,
                           Path,
                           "SecretRef cannot be resolved");
        }
        return {};
    }

} // namespace Prism::Application::Configuration::Validation
