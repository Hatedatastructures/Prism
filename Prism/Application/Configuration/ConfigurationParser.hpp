/**
 * @file ConfigurationParser.hpp
 * @brief Prism 配置的严格 glaze 解析入口。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationError.hpp>
#include <Prism/Application/Configuration/PreparedConfiguration.hpp>
#include <Prism/Application/Configuration/ConfigurationValidator.hpp>
#include <Prism/Application/Configuration/PrismConfigurationSchema.hpp>

#include <glaze/glaze.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Application::Configuration
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
        using Result = std::expected<PrismConfiguration, ConfigurationError>;
        using PreparedResult = std::expected<PreparedConfiguration, ConfigurationError>;
        using ValidationResult = ConfigurationValidator::Result;
        using SerializationResult = std::expected<std::string, ConfigurationError>;

        [[nodiscard]] static auto ParseJson(const std::string_view Json) -> Result
        {
            return Parse(ParseRequest{Json, {}});
        }

        /**
         * @brief 将完整配置值序列化为独立拥有的 JSON 文本。
         * @details 调用方负责先按其运行环境校验候选配置，并由应用层完成临时文件写入与原子替换。
         */
        [[nodiscard]] static auto SerializeJson(const PrismConfiguration &Configuration)
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

        /** @brief 校验借用 JSON 缓冲；调用方仍拥有并负责该缓冲的清理。 */
        [[nodiscard]] static auto Parse(ParseRequest Request) -> Result;

        /** @brief 管理 reload 只接受 secret references；值必须来自当前 owning generation。 */
        [[nodiscard]] static auto ParseForOperationsReload(std::string_view Json) -> Result;

        [[nodiscard]] static auto PrepareFile(LoadRequest Request) -> PreparedResult;

        [[nodiscard]] static auto Validate(const PrismConfiguration &Configuration)
            -> ValidationResult
        {
            return ConfigurationValidator::Validate(Configuration);
        }

        [[nodiscard]] static auto Validate(ValidationRequest Request) -> ValidationResult
        {
            return ConfigurationValidator::Validate(std::move(Request));
        }

        [[nodiscard]] static auto LoadFile(LoadRequest Request) -> Result;

        [[nodiscard]] static auto LoadFile(const std::filesystem::path &Path) -> Result
        {
            return LoadFile(LoadRequest{Path, {}});
        }
    };

    using Parser = ConfigurationParser;


    namespace
    {

        [[nodiscard]] auto ParseConfiguration(const std::string_view Json)
            -> std::expected<PrismConfiguration, ConfigurationError>
        {
            if (const auto Error = Schema::ValidateRequiredRootFields(Json))
            {
                return std::unexpected(*Error);
            }

            PrismConfiguration Configuration;
            Detail::SensitiveStringMapWiper Wiper(Configuration.Secrets);
            glz::context Context;
            if (const auto Error = glz::read<Detail::StrictJsonOptions>(
                    Configuration, Json, Context);
                Error)
            {
                return std::unexpected(Schema::ParseError(Error));
            }
            Wiper.Release();
            return Configuration;
        }

        [[nodiscard]] auto WithSecretLookup(ValidationOptions Options,
                                            SecretResolutionTransaction &Resolution)
            -> ValidationOptions
        {
            Options.Secrets = {};
            Options.SecretLookup = [&Resolution](const std::string_view Reference)
            { return Resolution.Resolve(Reference); };
            return Options;
        }

    } // namespace

    inline auto ConfigurationParser::Parse(ParseRequest Request) -> Result
    {
        auto Configuration = ParseConfiguration(Request.Json);
        if (!Configuration)
        {
            return std::unexpected(Configuration.error());
        }

        Detail::SensitiveStringMapWiper ConfigurationWiper(Configuration->Secrets);
        auto ExternalResolver = std::move(Request.Options.Secrets).TakeCallbackValue();
        auto Resolution = std::unique_ptr<SecretResolutionTransaction>(
            new SecretResolutionTransaction(Configuration->Secrets, std::move(ExternalResolver)));
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

    inline auto ConfigurationParser::ParseForOperationsReload(const std::string_view Json) -> Result
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

    inline auto ConfigurationParser::LoadFile(LoadRequest Request) -> Result
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

    inline auto ConfigurationParser::PrepareFile(LoadRequest Request) -> PreparedResult
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
        auto Resolution = std::unique_ptr<SecretResolutionTransaction>(
            new SecretResolutionTransaction(std::move(Configuration->Secrets),
                                            std::move(ExternalResolver)));
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

} // namespace Prism::Application::Configuration
