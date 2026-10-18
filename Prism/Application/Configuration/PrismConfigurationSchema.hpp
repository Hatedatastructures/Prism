/**
 * @file PrismConfigurationSchema.hpp
 * @brief Prism 配置的 v1 根字段预检合同。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Application/Configuration/PrismConfigurationJson.hpp>

#include <glaze/glaze.hpp>

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Application::Configuration::Schema
{

    inline constexpr std::array<std::string_view, 14> RequiredRootFields = {
        "SchemaVersion", "Runtime", "Listeners", "Builtins", "Protocols", "Carriers",
        "ProtocolBindings", "Accounts", "Routes", "Dns", "Statistics", "Operations",
        "HotReload", "Shutdown"};

    /** @brief 将 Glaze 解析错误映射为配置错误，保持 v1 分类。 */
    [[nodiscard]] inline auto ParseError(const glz::error_ctx &Error) -> ConfigurationError
    {
        ConfigurationErrorCode Code = ConfigurationErrorCode::Parse;
        if (Error.ec == glz::error_code::unknown_key)
        {
            Code = ConfigurationErrorCode::UnknownField;
        }
        else if (Error.ec == glz::error_code::missing_key)
        {
            Code = ConfigurationErrorCode::MissingField;
        }
        else if (Error.ec == glz::error_code::unexpected_enum ||
                 Error.ec == glz::error_code::get_wrong_type ||
                 Error.ec == glz::error_code::expected_true_or_false ||
                 Error.ec == glz::error_code::parse_number_failure ||
                 Error.ec == glz::error_code::invalid_variant_string ||
                 Error.ec == glz::error_code::invalid_variant_array)
        {
            Code = ConfigurationErrorCode::InvalidType;
        }
        return {Code, {}, glz::format_error(Error)};
    }

    /** @brief 先解析 JSON 并按固定顺序检查 v1 必填根字段。 */
    [[nodiscard]] inline auto ValidateRequiredRootFields(const std::string_view Json)
        -> std::optional<ConfigurationError>
    {
        glz::generic Document;
        if (const auto Error = glz::read_json(Document, Json); Error)
        {
            return ParseError(Error);
        }
        if (!Document.is_object())
        {
            return ConfigurationError{
                ConfigurationErrorCode::InvalidType,
                {},
                "PrismConfiguration must be a JSON object"};
        }

        const auto &Object = Document.get_object();
        for (const auto Key : RequiredRootFields)
        {
            if (Object.find(Key) == Object.end())
            {
                return ConfigurationError{
                    ConfigurationErrorCode::MissingField,
                    std::string(Key),
                    "required top-level configuration field is missing"};
            }
        }
        return std::nullopt;
    }

} // namespace Prism::Application::Configuration::Schema
