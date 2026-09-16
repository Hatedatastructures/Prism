/**
 * @file ConfigurationError.hpp
 * @brief Preview 配置错误类型。
 */
#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace Preview::Application::Configuration
{

    /** @brief 配置解析、校验和发布错误分类。 */
    enum class ConfigurationErrorCode : std::uint8_t
    {
        Parse = 0,
        UnknownField,
        MissingField,
        InvalidType,
        FileOpen,
        UnsupportedSchemaVersion,
        InvalidValue,
        InvalidPort = InvalidValue,
        InvalidTimeout = InvalidValue,
        DuplicateId,
        MissingReference,
        UnknownMuxMode,
        InvalidCarrierOptions,
        UnresolvedSecret,
        MissingCapability,
        InvalidConfiguration,
        InvalidGeneration,
        HotReloadDisabled,
        MissingAcknowledgement,
        WorkerRejected,
        PublishConflict,
    };

    /** @brief 带字段路径的配置错误。 */
    struct ConfigurationError
    {
        ConfigurationErrorCode Code{ConfigurationErrorCode::InvalidConfiguration};
        std::string Path;
        std::string Message;
    };

    using ConfigError = ConfigurationError;

    [[nodiscard]] inline auto MakeConfigurationError(const ConfigurationErrorCode Code,
                                                     std::string Path,
                                                     std::string Message) -> ConfigurationError
    {
        return {Code, std::move(Path), std::move(Message)};
    }

} // namespace Preview::Application::Configuration
