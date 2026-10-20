/** @file ConfigurationParser.cpp @brief Prism 配置解析、文件读取和 schema 预检实现。 */

#include <Prism/Application/Configuration/ConfigurationParser.hpp>
#include <Prism/Application/Configuration/ConfigurationValidator.hpp>
#include <Prism/Application/Configuration/Detail/PreparedConfigurationSecrets.hpp>
#include <Prism/Application/Configuration/PrismConfigurationJson.hpp>

#include <glaze/glaze.hpp>

#include <array>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Application::Configuration
{

    namespace
    {

        constexpr auto StrictJsonOptions = []
        {
            glz::opts Options{};
            Options.error_on_unknown_keys = true;
            Options.error_on_missing_keys = false;
            return Options;
        }();

        constexpr std::array<std::string_view, 14> RequiredRootFields = {
            "SchemaVersion", "Runtime", "Listeners", "Builtins", "Protocols", "Carriers",
            "ProtocolBindings", "Accounts", "Routes", "Dns", "Statistics", "Operations",
            "HotReload", "Shutdown"};

        [[nodiscard]] auto ParseError(const glz::error_ctx &Error) -> ConfigurationError
        {
            auto Code = ConfigurationErrorCode::Parse;
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

        [[nodiscard]] auto ValidateRequiredRootFields(const std::string_view Json)
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

        [[nodiscard]] auto ParseConfiguration(const std::string_view Json)
            -> std::expected<PrismConfiguration, ConfigurationError>
        {
            if (const auto Error = ValidateRequiredRootFields(Json))
            {
                return std::unexpected(*Error);
            }

            PrismConfiguration Configuration;
            Detail::SensitiveStringMapWiper Wiper(Configuration.Secrets);
            glz::context Context;
            if (const auto Error = glz::read<StrictJsonOptions>(Configuration, Json, Context); Error)
            {
                return std::unexpected(ParseError(Error));
            }
            Wiper.Release();
            return Configuration;
        }

        [[nodiscard]] auto WithSecretLookup(
            ValidationOptions Options,
            Detail::SecretResolutionTransaction &Resolution) -> ValidationOptions
        {
            Options.Secrets = {};
            Options.SecretLookup = [&Resolution](const std::string_view Reference)
            { return Resolution.Resolve(Reference); };
            return Options;
        }

    } // namespace

    auto ConfigurationParser::ParseJson(const std::string_view Json) -> Result
    {
        return Parse(ParseRequest{Json, {}});
    }

    auto ConfigurationParser::SerializeJson(const PrismConfiguration &Configuration)
        -> SerializationResult
    {
        auto Json = glz::write_json(Configuration);
        if (!Json)
        {
            return std::unexpected(ConfigurationError{
                ConfigurationErrorCode::InvalidConfiguration,
                {},
                glz::format_error(Json.error())});
        }
        return std::move(*Json);
    }

    auto ConfigurationParser::Parse(ParseRequest Request) -> Result
    {
        auto Configuration = ParseConfiguration(Request.Json);
        if (!Configuration)
        {
            return std::unexpected(Configuration.error());
        }

        Detail::SensitiveStringMapWiper ConfigurationWiper(Configuration->Secrets);
        auto ExternalResolver = std::move(Request.Options.Secrets).TakeCallbackValue();
        auto Resolution = std::make_unique<Detail::SecretResolutionTransaction>(
            Configuration->Secrets, std::move(ExternalResolver));
        auto Options = WithSecretLookup(std::move(Request.Options), *Resolution);
        if (const auto Validation = ConfigurationValidator::Validate(
                ValidationRequest{*Configuration, std::move(Options)});
            !Validation)
        {
            return std::unexpected(Validation.error());
        }
        ConfigurationWiper.Release();
        return std::move(*Configuration);
    }

    auto ConfigurationParser::ParseForOperationsReload(const std::string_view Json) -> Result
    {
        auto Configuration = ParseConfiguration(Json);
        if (!Configuration)
        {
            return std::unexpected(Configuration.error());
        }
        Detail::SensitiveStringMapWiper SecretWiper(Configuration->Secrets);
        bool HasInlineSecret = !Configuration->Secrets.empty();
        for (auto &Account : Configuration->Accounts)
        {
            Detail::SensitiveStringWiper CredentialWiper(Account.Credential);
            HasInlineSecret = HasInlineSecret || !Account.Credential.empty();
            for (auto &[Protocol, Credential] : Account.Credentials)
            {
                (void)Protocol;
                Detail::SensitiveStringWiper ProtocolCredentialWiper(Credential);
                HasInlineSecret = HasInlineSecret || !Credential.empty();
            }
        }
        for (auto &Protocol : Configuration->Protocols)
        {
            if (Protocol.Quic)
            {
                Detail::SensitiveStringWiper QuicUuidWiper(Protocol.Quic->Uuid);
                HasInlineSecret = HasInlineSecret || !Protocol.Quic->Uuid.empty();
            }
        }
        if (HasInlineSecret)
        {
            return std::unexpected(MakeConfigurationError(
                ConfigurationErrorCode::UnresolvedSecret, "Configuration",
                "operations reload accepts references only; secret values come from the active generation"));
        }
        return std::move(*Configuration);
    }

    auto ConfigurationParser::PrepareFile(LoadRequest Request) -> PreparedResult
    {
        std::ifstream File(Request.Path, std::ios::binary);
        if (!File)
        {
            return std::unexpected(ConfigurationError{
                ConfigurationErrorCode::FileOpen,
                Request.Path.string(),
                "cannot open PrismConfiguration.json"});
        }

        std::string Json;
        Detail::SensitiveStringWiper JsonWiper(Json);
        Json.assign(std::istreambuf_iterator<char>(File), std::istreambuf_iterator<char>());
        auto Configuration = ParseConfiguration(Json);
        if (!Configuration)
        {
            return std::unexpected(Configuration.error());
        }

        Detail::SensitiveStringMapWiper ConfigurationWiper(Configuration->Secrets);
        auto ExternalResolver = std::move(Request.Options.Secrets).TakeCallbackValue();
        auto Resolution = std::make_unique<Detail::SecretResolutionTransaction>(
            std::move(Configuration->Secrets), std::move(ExternalResolver));
        auto Options = WithSecretLookup(std::move(Request.Options), *Resolution);
        Options.CheckSecrets = true;
        if (const auto Validation = ConfigurationValidator::Validate(
                ValidationRequest{*Configuration, std::move(Options)});
            !Validation)
        {
            return std::unexpected(Validation.error());
        }

        Resolution->Seal();
        return PreparedConfiguration{std::move(*Configuration), std::move(Resolution)};
    }

    auto ConfigurationParser::LoadFile(LoadRequest Request) -> Result
    {
        std::ifstream File(Request.Path, std::ios::binary);
        if (!File)
        {
            return std::unexpected(ConfigurationError{
                ConfigurationErrorCode::FileOpen,
                Request.Path.string(),
                "cannot open PrismConfiguration.json"});
        }

        std::string Json;
        Detail::SensitiveStringWiper JsonWiper(Json);
        Json.assign(std::istreambuf_iterator<char>(File), std::istreambuf_iterator<char>());
        return Parse(ParseRequest{Json, std::move(Request.Options)});
    }

} // namespace Prism::Application::Configuration
