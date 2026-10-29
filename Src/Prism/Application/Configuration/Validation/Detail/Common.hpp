/**
 * @file Common.hpp
 * @brief 配置校验共享的错误、标识符和文本规则。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Application/Configuration/Validation/ValidationTypes.hpp>

#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <utility>

namespace Prism::Application::Configuration::Validation
{

    using Result = Prism::Application::Configuration::ValidationResult;

    [[nodiscard]] inline auto Failure(const ConfigurationErrorCode Code,
                                      std::string Path,
                                      std::string Message) -> Result
    {
        return std::unexpected(MakeConfigurationError(Code, std::move(Path), std::move(Message)));
    }

    [[nodiscard]] inline auto RequireText(const std::string &Value,
                                           const std::string &Path,
                                           const std::string_view Message) -> Result
    {
        if (Value.empty())
        {
            return Failure(ConfigurationErrorCode::MissingField, Path, std::string(Message));
        }
        return {};
    }

    [[nodiscard]] inline auto RequireTextList(const std::vector<std::string> &Values,
                                              const std::string &Path,
                                              const std::string_view Message) -> Result
    {
        if (Values.empty())
        {
            return Failure(ConfigurationErrorCode::MissingField, Path, std::string(Message));
        }
        for (std::size_t Index = 0; Index < Values.size(); ++Index)
        {
            if (Values[Index].empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + "[" + std::to_string(Index) + "]",
                               "value must not be empty");
            }
        }
        return {};
    }

    [[nodiscard]] inline auto AddId(std::unordered_set<std::string> &Ids,
                                    const std::string &Id,
                                    const std::string &Path) -> Result
    {
        if (Id.empty())
        {
            return Failure(ConfigurationErrorCode::InvalidValue, Path, "Id is required");
        }
        if (!Ids.insert(Id).second)
        {
            return Failure(ConfigurationErrorCode::DuplicateId,
                           Path,
                           "duplicate configuration Id");
        }
        return {};
    }

} // namespace Prism::Application::Configuration::Validation
