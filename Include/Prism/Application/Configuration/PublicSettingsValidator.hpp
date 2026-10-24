/**
 * @file PublicSettingsValidator.hpp
 * @brief Prism 公共设置的纯配置错误校验合同。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Application/Configuration/PrismConfiguration.hpp>

#include <cstdint>
#include <expected>
#include <string_view>

namespace Prism::Application::Configuration
{

    /** @brief 校验日志、Operations endpoint 和公共 timeout 设置。 */
    class PublicSettingsValidator final
    {
    public:
        using Result = std::expected<void, ConfigurationError>;

        [[nodiscard]] static auto ValidateLogging(const LoggingConfiguration &Configuration) -> Result;

        [[nodiscard]] static auto ValidateOperationsEndpoint(std::string_view Endpoint) -> Result;

        [[nodiscard]] static auto ValidateTimeout(std::uint32_t Timeout,
                                                  std::string_view Path) -> Result;
    };
} // namespace Prism::Application::Configuration
