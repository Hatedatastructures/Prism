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
#include <charconv>
#include <string>

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


    namespace
    {

        constexpr std::uint32_t MaxTimeoutMs = 600000U;
        constexpr std::uint64_t MinRotateBytes = 4096ULL;
        constexpr std::uint64_t MaxRotateBytes = 1024ULL * 1024ULL * 1024ULL;
        constexpr std::uint32_t MaxRotateFiles = 64U;

        [[nodiscard]] auto Failure(const ConfigurationErrorCode Code,
                                   const std::string_view Path,
                                   const std::string_view Message)
            -> PublicSettingsValidator::Result
        {
            return std::unexpected(
                MakeConfigurationError(Code, std::string(Path), std::string(Message)));
        }

        [[nodiscard]] auto IsLoggingLevel(const std::string_view Level) noexcept -> bool
        {
            return Level == "Trace" || Level == "Debug" || Level == "Info" ||
                   Level == "Access" || Level == "Warn" || Level == "Error" ||
                   Level == "Critical" || Level == "Off";
        }

    } // namespace

    inline auto PublicSettingsValidator::ValidateLogging(const LoggingConfiguration &Configuration)
        -> Result
    {
        if (!IsLoggingLevel(Configuration.Level))
        {
            return Failure(ConfigurationErrorCode::InvalidValue, "Logging.Level",
                           "Level must be Trace, Debug, Info, Access, Warn, Error, Critical, or Off");
        }
        if (Configuration.RenderMode != "CompactHuman" &&
            Configuration.RenderMode != "HumanWithFields" &&
            Configuration.RenderMode != "Structured")
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Logging.RenderMode",
                           "RenderMode must be CompactHuman, HumanWithFields, or Structured");
        }
        if (Configuration.Directory.empty())
        {
            return Failure(ConfigurationErrorCode::InvalidValue, "Logging.Directory",
                           "Directory must not be empty");
        }
        if (Configuration.FileName.empty() || Configuration.FileName == "." ||
            Configuration.FileName == ".." ||
            Configuration.FileName.find_first_of("/\\:") != std::string::npos)
        {
            return Failure(ConfigurationErrorCode::InvalidValue, "Logging.FileName",
                           "FileName must be a single file name");
        }
        if (Configuration.RotateBytes < MinRotateBytes ||
            Configuration.RotateBytes > MaxRotateBytes)
        {
            return Failure(ConfigurationErrorCode::InvalidValue, "Logging.RotateBytes",
                           "RotateBytes must be between 4096 and 1073741824");
        }
        if (Configuration.RotateFiles == 0U ||
            Configuration.RotateFiles > MaxRotateFiles)
        {
            return Failure(ConfigurationErrorCode::InvalidValue, "Logging.RotateFiles",
                           "RotateFiles must be between 1 and 64");
        }
        if (Configuration.FlushIntervalMs == 0U ||
            Configuration.FlushIntervalMs > MaxTimeoutMs)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Logging.FlushIntervalMs",
                           "FlushIntervalMs must be between 1 and 600000 milliseconds");
        }
        return {};
    }

    inline auto PublicSettingsValidator::ValidateOperationsEndpoint(const std::string_view Endpoint)
        -> Result
    {
        if (Endpoint.empty())
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Operations.Endpoint",
                           "operations Endpoint is required");
        }

        std::string_view Address;
        std::string_view PortText;
        if (Endpoint.front() == '[')
        {
            const auto Close = Endpoint.find(']');
            if (Close == std::string::npos || Close + 2U > Endpoint.size() ||
                Endpoint[Close + 1U] != ':')
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Operations.Endpoint",
                               "operations Endpoint must be address:port");
            }
            Address = Endpoint.substr(1U, Close - 1U);
            PortText = Endpoint.substr(Close + 2U);
        }
        else
        {
            const auto Separator = Endpoint.rfind(':');
            if (Separator == std::string::npos || Endpoint.find(':') != Separator)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Operations.Endpoint",
                               "operations IPv6 endpoints must use brackets");
            }
            Address = Endpoint.substr(0, Separator);
            PortText = Endpoint.substr(Separator + 1U);
        }

        if (Address != "127.0.0.1" && Address != "localhost" && Address != "::1")
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Operations.Endpoint",
                           "operations listener must use a loopback address");
        }
        if (PortText.empty())
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Operations.Endpoint",
                           "operations port must be between 0 and 65535");
        }

        std::uint32_t Port = 0;
        const auto [End, Error] = std::from_chars(
            PortText.data(), PortText.data() + PortText.size(), Port, 10);
        if (Error != std::errc{} || End != PortText.data() + PortText.size() || Port > 65535U)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           "Operations.Endpoint",
                           "operations port must be between 0 and 65535");
        }
        return {};
    }

    inline auto PublicSettingsValidator::ValidateTimeout(const std::uint32_t Timeout,
                                                  const std::string_view Path) -> Result
    {
        if (Timeout == 0U || Timeout > MaxTimeoutMs)
        {
            return Failure(ConfigurationErrorCode::InvalidValue, Path,
                           "timeout must be between 1 and 600000 milliseconds");
        }
        return {};
    }

} // namespace Prism::Application::Configuration
