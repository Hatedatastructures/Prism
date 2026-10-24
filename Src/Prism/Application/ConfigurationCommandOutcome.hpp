/** @file ConfigurationCommandOutcome.hpp @brief 配置首因转换为安全公开校验结果的接口。 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Operations/Models.hpp>

#include <string_view>

namespace Prism::Application::ConfigurationCommandOutcome
{

    [[nodiscard]] auto CodeName(Configuration::ConfigurationErrorCode Code) noexcept
        -> std::string_view;

    [[nodiscard]] auto Invalid(
        Prism::RequestId Correlation,
        const Configuration::ConfigurationError &Error) -> Prism::Operations::CommandResult;

} // namespace Prism::Application::ConfigurationCommandOutcome
