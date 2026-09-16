/**
 * @file ConfigurationParser.hpp
 * @brief Preview 配置的严格 glaze 解析入口。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationError.hpp>
#include <Preview/Application/Configuration/ConfigurationValidator.hpp>
#include <Preview/Application/Configuration/PreviewConfigurationJson.hpp>

#include <glaze/glaze.hpp>

#include <array>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

namespace Preview::Application::Configuration
{

    namespace Detail
    {

        inline constexpr auto StrictJsonOptions = []
        {
            glz::opts Options{};
            Options.error_on_unknown_keys = true;
            Options.error_on_missing_keys = false;
            return Options;
        }();

        [[nodiscard]] inline auto ParseError(const glz::error_ctx &Error,
                                             const std::string_view Json) -> ConfigurationError;

        [[nodiscard]] inline auto ValidateTopLevelKeys(const std::string_view Json)
            -> std::optional<ConfigurationError>
        {
            glz::generic Document;
            if (const auto Error = glz::read_json(Document, Json); Error)
            {
                return ParseError(Error, Json);
            }
            if (!Document.is_object())
            {
                return ConfigurationError{
                    ConfigurationErrorCode::InvalidType,
                    {},
                    "PreviewConfiguration must be a JSON object"};
            }

            static constexpr std::array<std::string_view, 14> RequiredKeys = {
                "SchemaVersion", "Runtime", "Listeners", "Builtins", "Protocols", "Carriers",
                "ProtocolBindings", "Accounts", "Routes", "Dns", "Statistics", "Operations",
                "HotReload", "Shutdown"};
            const auto &Object = Document.get_object();
            for (const auto Key : RequiredKeys)
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

        [[nodiscard]] inline auto ParseError(const glz::error_ctx &Error,
                                             const std::string_view Json) -> ConfigurationError
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
            (void)Json;
            return {Code, {}, glz::format_error(Error)};
        }

    } // namespace Detail

    /** @brief 严格解析请求。 */
    struct ParseRequest
    {
        std::string_view Json;
        ValidationOptions Options{};
    };

    /** @brief 文件解析请求。 */
    struct LoadRequest
    {
        std::filesystem::path Path;
        ValidationOptions Options{};
    };

    class ConfigurationParser final
    {
    public:
        using Result = std::expected<PreviewConfiguration, ConfigurationError>;
        using ValidationResult = ConfigurationValidator::Result;

        [[nodiscard]] static auto ParseJson(const std::string_view Json) -> Result
        {
            return Parse(ParseRequest{Json, {}});
        }

        [[nodiscard]] static auto Parse(ParseRequest Request) -> Result
        {
            if (const auto Error = Detail::ValidateTopLevelKeys(Request.Json))
            {
                return std::unexpected(*Error);
            }
            PreviewConfiguration Configuration;
            glz::context Context;
            if (const auto Error = glz::read<Detail::StrictJsonOptions>(
                    Configuration, Request.Json, Context);
                Error)
            {
                return std::unexpected(Detail::ParseError(Error, Request.Json));
            }

            if (const auto Error = ConfigurationValidator::Validate(
                    ValidationRequest{Configuration, std::move(Request.Options)});
                !Error)
            {
                return std::unexpected(Error.error());
            }
            return Configuration;
        }

        [[nodiscard]] static auto Validate(const PreviewConfiguration &Configuration)
            -> ValidationResult
        {
            return ConfigurationValidator::Validate(Configuration);
        }

        [[nodiscard]] static auto Validate(ValidationRequest Request) -> ValidationResult
        {
            return ConfigurationValidator::Validate(std::move(Request));
        }

        [[nodiscard]] static auto LoadFile(LoadRequest Request) -> Result
        {
            std::ifstream File(Request.Path, std::ios::binary);
            if (!File)
            {
                return std::unexpected(ConfigurationError{
                    ConfigurationErrorCode::FileOpen,
                    Request.Path.string(),
                    "cannot open PreviewConfiguration.json"});
            }
            const std::string Json((std::istreambuf_iterator<char>(File)),
                                   std::istreambuf_iterator<char>());
            return Parse(ParseRequest{Json, std::move(Request.Options)});
        }

        [[nodiscard]] static auto LoadFile(const std::filesystem::path &Path) -> Result
        {
            return LoadFile(LoadRequest{Path, {}});
        }
    };

    using Parser = ConfigurationParser;

} // namespace Preview::Application::Configuration
