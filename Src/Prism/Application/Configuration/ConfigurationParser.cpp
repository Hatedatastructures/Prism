/** @file ConfigurationParser.cpp @brief Prism 配置解析、文件读取和 schema 预检实现。 */

#include <Prism/Application/Configuration/ConfigurationParser.hpp>
#include <Prism/Application/Configuration/ConfigurationValidator.hpp>
#include <Prism/Application/Configuration/Detail/Secrets.hpp>
#include <Prism/Application/Configuration/PrismConfigurationJson.hpp>

#include <glaze/glaze.hpp>

#include <array>
#include <cstddef>
#include <expected>
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

        auto WipeGenericStrings(glz::generic &Value) noexcept -> void;

        [[nodiscard]] auto PreflightConfiguration(const std::string_view Json)
            -> std::expected<glz::generic, ConfigurationError>
        {
            glz::generic Document;
            if (const auto Error = glz::read_json(Document, Json); Error)
            {
                const auto ParseFailure = ParseError(Error);
                WipeGenericStrings(Document);
                return std::unexpected(ParseFailure);
            }
            if (!Document.is_object())
            {
                const ConfigurationError Failure{
                    ConfigurationErrorCode::InvalidType,
                    {},
                    "PrismConfiguration must be a JSON object"};
                WipeGenericStrings(Document);
                return std::unexpected(Failure);
            }

            const auto &Object = Document.get_object();
            for (const auto Key : RequiredRootFields)
            {
                if (Object.find(Key) == Object.end())
                {
                    const ConfigurationError Failure{
                        ConfigurationErrorCode::MissingField,
                        std::string(Key),
                        "required top-level configuration field is missing"};
                    WipeGenericStrings(Document);
                    return std::unexpected(Failure);
                }
            }
            return Document;
        }

        [[nodiscard]] auto ArrayElementCount(const glz::generic &Document,
                                             const std::string_view Key) -> std::size_t
        {
            const auto &Object = Document.get_object();
            const auto Found = Object.find(Key);
            if (Found == Object.end() || !Found->second.is_array())
            {
                return 0U;
            }
            return Found->second.get_array().size();
        }

        auto WipeString(std::string &Value) noexcept -> void
        {
            volatile char *Bytes = Value.data();
            for (std::size_t Index = 0; Index < Value.size(); ++Index)
            {
                Bytes[Index] = '\0';
            }
            Value.clear();
        }

        auto WipeGenericStrings(glz::generic &Value) noexcept -> void
        {
            if (Value.is_string())
            {
                WipeString(Value.get<std::string>());
                return;
            }
            if (Value.is_array())
            {
                for (auto &Element : Value.get_array())
                {
                    WipeGenericStrings(Element);
                }
                return;
            }
            if (!Value.is_object())
            {
                return;
            }
            for (auto &[Key, Element] : Value.get_object())
            {
                (void)Key;
                WipeGenericStrings(Element);
            }
        }

        class ConfigurationInlineSecretWiper final
        {
        public:
            explicit ConfigurationInlineSecretWiper(PrismConfiguration &Configuration) noexcept
                : Configuration_(&Configuration)
            {
            }

            ~ConfigurationInlineSecretWiper()
            {
                Wipe();
            }

            ConfigurationInlineSecretWiper(const ConfigurationInlineSecretWiper &) = delete;
            auto operator=(const ConfigurationInlineSecretWiper &)
                -> ConfigurationInlineSecretWiper & = delete;

            auto Release() noexcept -> void
            {
                Configuration_ = nullptr;
            }

        private:
            auto Wipe() noexcept -> void
            {
                if (Configuration_ == nullptr)
                {
                    return;
                }
                for (auto &Account : Configuration_->Accounts)
                {
                    WipeString(Account.Credential);
                    for (auto &[Protocol, Credential] : Account.Credentials)
                    {
                        (void)Protocol;
                        WipeString(Credential);
                    }
                }
                for (auto &Protocol : Configuration_->Protocols)
                {
                    if (Protocol.Quic)
                    {
                        WipeString(Protocol.Quic->Uuid);
                    }
                }
            }

            PrismConfiguration *Configuration_{nullptr};
        };

        [[nodiscard]] auto HasInlineSecrets(const PrismConfiguration &Configuration) -> bool
        {
            if (!Configuration.Secrets.empty())
            {
                return true;
            }
            for (const auto &Account : Configuration.Accounts)
            {
                if (!Account.Credential.empty())
                {
                    return true;
                }
                for (const auto &[Protocol, Credential] : Account.Credentials)
                {
                    (void)Protocol;
                    if (!Credential.empty())
                    {
                        return true;
                    }
                }
            }
            for (const auto &Protocol : Configuration.Protocols)
            {
                if (Protocol.Quic && !Protocol.Quic->Uuid.empty())
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] auto ParseConfiguration(const std::string_view Json)
            -> std::expected<PrismConfiguration, ConfigurationError>
        {
            auto Preflight = PreflightConfiguration(Json);
            if (!Preflight)
            {
                return std::unexpected(Preflight.error());
            }

            auto &Document = *Preflight;
            const auto AccountCount = ArrayElementCount(Document, "Accounts");
            const auto ProtocolCount = ArrayElementCount(Document, "Protocols");
            const auto CarrierCount = ArrayElementCount(Document, "Carriers");
            const auto AccountGroupCount = ArrayElementCount(Document, "AccountGroups");
            const auto BindingCount = ArrayElementCount(Document, "ProtocolBindings");
            WipeGenericStrings(Document);

            PrismConfiguration Configuration;
            Configuration.Accounts.reserve(AccountCount);
            Configuration.Protocols.reserve(ProtocolCount);
            Configuration.Carriers.reserve(CarrierCount);
            Configuration.AccountGroups.reserve(AccountGroupCount);
            Configuration.ProtocolBindings.reserve(BindingCount);

            Detail::SensitiveStringMapWiper SecretWiper(Configuration.Secrets);
            ConfigurationInlineSecretWiper InlineWiper(Configuration);
            glz::context Context;
            if (const auto Error = glz::read<StrictJsonOptions>(Configuration, Json, Context); Error)
            {
                return std::unexpected(ParseError(Error));
            }
            InlineWiper.Release();
            SecretWiper.Release();
            return std::move(Configuration);
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
        ConfigurationInlineSecretWiper InlineWiper(*Configuration);
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
        InlineWiper.Release();
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
        ConfigurationInlineSecretWiper InlineWiper(*Configuration);
        if (HasInlineSecrets(*Configuration))
        {
            return std::unexpected(MakeConfigurationError(
                ConfigurationErrorCode::UnresolvedSecret, "Configuration",
                "operations reload accepts references only; secret values come from the active generation"));
        }
        InlineWiper.Release();
        SecretWiper.Release();
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
        ConfigurationInlineSecretWiper InlineWiper(*Configuration);
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
        InlineWiper.Release();
        ConfigurationWiper.Release();
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
