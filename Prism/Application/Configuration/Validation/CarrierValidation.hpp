/**
 * @file CarrierValidation.hpp
 * @brief TLS/carrier typed options and carrier match 规则。
 */
#pragma once

#include <Prism/Application/Configuration/PublicSettingsValidator.hpp>
#include <Prism/Application/Configuration/Validation/ProtocolIndependentValidation.hpp>
#include <Prism/Application/Configuration/Validation/ReferenceValidation.hpp>
#include <Prism/Application/Configuration/Validation/SecretValidation.hpp>

#include <string>
#include <string_view>
#include <variant>

namespace Prism::Application::Configuration::Validation
{

    [[nodiscard]] inline auto ValidateCarrierMatch(const Prism::Contract::CarrierMatchOptions &Match,
                                                    const std::string &Path) -> Result
    {
        if (const auto ResultValue = ValidateServerNames(
                Match.ServerNames, Path + ".ServerNames",
                ServerNameValidationPolicy{ServerNameRequirement::Optional, true, true});
            !ResultValue)
        {
            return ResultValue;
        }
        return ValidateAlpnList(Match.Alpn, Path + ".Alpn");
    }

    /**
     * @brief carrier 冷路径校验借用上下文。
     * @details 只借用当前配置、错误 path 和 secret/capability 校验选项；退出后不持有
     *          caller，不启动异步任务，不处理取消或半关闭，结果只返回 typed validation error。
     *          所有调用在当前 caller executor 的同步冷路径执行。
     */
    struct CarrierOptionsValidationContext final
    {
        const Prism::Contract::CarrierConfiguration &Carrier;
        const std::string &Path;
        const std::string OptionsPath;
        const ValidationOptions &Options;
    };

    [[nodiscard]] inline auto RequireCarrierBuiltin(
        const CarrierOptionsValidationContext &Context,
        const std::string_view Expected) -> Result
    {
        if (CanonicalBuiltinName("carrier", Context.Carrier.Builtin) != Expected)
        {
            return Failure(ConfigurationErrorCode::InvalidCarrierOptions,
                           Context.Path + ".Options.Type",
                           "carrier Builtin does not match typed Options");
        }
        return {};
    }

    /**
     * @brief 各 typed carrier options 的正式冷校验 overload。
     * @details 每个 overload 只负责一种配置类型，按既有顺序返回 typed error；不拥有输入，
     *          不启动异步任务，也不改变 caller 的 executor 或生命周期。
     */
    [[nodiscard]] inline auto ValidateCarrierOptions(
        const Prism::Contract::NativeTlsOptions &TypedOptions,
        const CarrierOptionsValidationContext &Context) -> Result
    {
        if (const auto ResultValue = RequireCarrierBuiltin(Context, "native"); !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.CertificateFile,
                Context.OptionsPath + ".CertificateFile",
                "CertificateFile is required");
            !ResultValue)
        {
            return ResultValue;
        }
        return RequireText(TypedOptions.PrivateKeyFile,
                           Context.OptionsPath + ".PrivateKeyFile",
                           "PrivateKeyFile is required");
    }

    [[nodiscard]] inline auto ValidateCarrierOptions(
        const Prism::Contract::RealityOptions &TypedOptions,
        const CarrierOptionsValidationContext &Context) -> Result
    {
        if (const auto ResultValue = RequireCarrierBuiltin(Context, "reality"); !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.HandshakeTarget,
                Context.OptionsPath + ".HandshakeTarget",
                "HandshakeTarget is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateHostPort(
                TypedOptions.HandshakeTarget,
                Context.OptionsPath + ".HandshakeTarget",
                "HandshakeTarget");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateServerNames(
                TypedOptions.ServerNames,
                Context.OptionsPath + ".ServerNames",
                ServerNameValidationPolicy{ServerNameRequirement::Required, false, true});
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateSecretReference(
                TypedOptions.PrivateKeyRef,
                Context.OptionsPath + ".PrivateKeyRef",
                Context.Options);
            !ResultValue)
        {
            return ResultValue;
        }
        return ValidateShortIds(TypedOptions.ShortIds, Context.OptionsPath + ".ShortIds");
    }

    [[nodiscard]] inline auto ValidateCarrierOptions(
        const Prism::Contract::ShadowTlsOptions &TypedOptions,
        const CarrierOptionsValidationContext &Context) -> Result
    {
        if (const auto ResultValue = RequireCarrierBuiltin(Context, "shadowtls"); !ResultValue)
        {
            return ResultValue;
        }
        if (TypedOptions.Version != 3U)
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Context.OptionsPath + ".Version",
                           "ShadowTls Version must be 3");
        }
        if (const auto ResultValue = ValidateSecretReference(
                TypedOptions.PasswordSecretRef,
                Context.OptionsPath + ".PasswordSecretRef",
                Context.Options);
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.HandshakeDest,
                Context.OptionsPath + ".HandshakeDest",
                "HandshakeDest is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateHostPort(
                TypedOptions.HandshakeDest,
                Context.OptionsPath + ".HandshakeDest",
                "HandshakeDest");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateServerNames(
                TypedOptions.ServerNames,
                Context.OptionsPath + ".ServerNames",
                ServerNameValidationPolicy{ServerNameRequirement::Required, false, false});
            !ResultValue)
        {
            return ResultValue;
        }
        return PublicSettingsValidator::ValidateTimeout(
            TypedOptions.HandshakeTimeoutMs,
            Context.OptionsPath + ".HandshakeTimeoutMs");
    }

    [[nodiscard]] inline auto ValidateCarrierOptions(
        const Prism::Contract::RestlsOptions &TypedOptions,
        const CarrierOptionsValidationContext &Context) -> Result
    {
        if (const auto ResultValue = RequireCarrierBuiltin(Context, "restls"); !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateServerNames(
                TypedOptions.ServerNames,
                Context.OptionsPath + ".ServerNames",
                ServerNameValidationPolicy{ServerNameRequirement::Required, false, false});
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.Host, Context.OptionsPath + ".Host", "Host is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateHostPort(
                TypedOptions.Host, Context.OptionsPath + ".Host", "Host");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateSecretReference(
                TypedOptions.PasswordSecretRef,
                Context.OptionsPath + ".PasswordSecretRef",
                Context.Options);
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.VersionHint,
                Context.OptionsPath + ".VersionHint",
                "VersionHint is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (!IsValidToken(TypedOptions.VersionHint, 32U))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Context.OptionsPath + ".VersionHint",
                           "VersionHint must be a non-empty ASCII token");
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.RestlsScript,
                Context.OptionsPath + ".RestlsScript",
                "RestlsScript is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (!IsValidRestlsScript(TypedOptions.RestlsScript))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Context.OptionsPath + ".RestlsScript",
                           "RestlsScript does not match the supported rule syntax");
        }
        return PublicSettingsValidator::ValidateTimeout(
            TypedOptions.HandshakeTimeoutMs,
            Context.OptionsPath + ".HandshakeTimeoutMs");
    }

    [[nodiscard]] inline auto ValidateCarrierOptions(
        const Prism::Contract::WebSocketOptions &TypedOptions,
        const CarrierOptionsValidationContext &Context) -> Result
    {
        if (Context.Carrier.Builtin != "ws" && Context.Carrier.Builtin != "websocket")
        {
            return Failure(ConfigurationErrorCode::InvalidCarrierOptions,
                           Context.Path + ".Options.Type",
                           "carrier Builtin does not match typed Options");
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.Path, Context.OptionsPath + ".Path", "Path is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateHttpPath(
                TypedOptions.Path, Context.OptionsPath + ".Path");
            !ResultValue)
        {
            return ResultValue;
        }
        return ValidateOptionalHost(TypedOptions.Host, Context.OptionsPath + ".Host");
    }

    [[nodiscard]] inline auto ValidateCarrierOptions(
        const Prism::Contract::XhttpOptions &TypedOptions,
        const CarrierOptionsValidationContext &Context) -> Result
    {
        if (const auto ResultValue = RequireCarrierBuiltin(Context, "xhttp"); !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.Path, Context.OptionsPath + ".Path", "Path is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateHttpPath(
                TypedOptions.Path, Context.OptionsPath + ".Path");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateOptionalHost(
                TypedOptions.Host, Context.OptionsPath + ".Host");
            !ResultValue)
        {
            return ResultValue;
        }
        if (!IsXhttpMode(TypedOptions.Mode))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Context.OptionsPath + ".Mode",
                           "unknown Xhttp mode");
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateCarrierOptions(
        const Prism::Contract::GunOptions &TypedOptions,
        const CarrierOptionsValidationContext &Context) -> Result
    {
        if (const auto ResultValue = RequireCarrierBuiltin(Context, "gun"); !ResultValue)
        {
            return ResultValue;
        }
        if (TypedOptions.Mode != "GunLite" && TypedOptions.Mode != "Grpc")
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Context.OptionsPath + ".Mode",
                           "Gun mode must be GunLite or Grpc");
        }
        if (const auto ResultValue = ValidateServerNames(
                TypedOptions.ServerNames,
                Context.OptionsPath + ".ServerNames",
                ServerNameValidationPolicy{ServerNameRequirement::Required, false, false});
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.Path, Context.OptionsPath + ".Path", "Path is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateHttpPath(
                TypedOptions.Path, Context.OptionsPath + ".Path");
            !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = RequireText(
                TypedOptions.ServiceName,
                Context.OptionsPath + ".ServiceName",
                "ServiceName is required");
            !ResultValue)
        {
            return ResultValue;
        }
        if (!IsValidToken(TypedOptions.ServiceName, 255U))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Context.OptionsPath + ".ServiceName",
                           "ServiceName must be an ASCII token");
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateCarrier(const Prism::Contract::CarrierConfiguration &Carrier,
                                              const std::string &Path,
                                              const ValidationOptions &Options) -> Result
    {
        if (IsStackProtocolBuiltin(Carrier.Builtin))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Path + ".Builtin",
                           "AnyTLS and TrustTunnel are stack protocols and cannot be carriers");
        }

        const CarrierOptionsValidationContext Context{Carrier, Path, Path + ".Options", Options};
        return std::visit(
            [&Context](const auto &TypedOptions) -> Result
            { return ValidateCarrierOptions(TypedOptions, Context); },
            Carrier.Options);
    }

    [[nodiscard]] inline auto ValidateCarriers(
        const std::vector<Prism::Contract::CarrierConfiguration> &Carriers,
        const ValidationOptions &Options,
        std::unordered_set<std::string> &Ids) -> Result
    {
        for (std::size_t Index = 0; Index < Carriers.size(); ++Index)
        {
            const auto &Carrier = Carriers[Index];
            const auto Path = "Carriers[" + std::to_string(Index) + "]";
            if (const auto ResultValue = AddId(Ids, Carrier.Id, Path + ".Id"); !ResultValue)
            {
                return ResultValue;
            }
            if (Carrier.Name.empty() || Carrier.Builtin.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "carrier Name and Builtin are required");
            }
            if (Options.Builtins)
            {
                if (!FindBuiltinDescriptor(*Options.Builtins, "carrier", Carrier.Builtin))
                {
                    return Failure(ConfigurationErrorCode::MissingReference,
                                   Path + ".Builtin",
                                   "carrier builtin is unavailable in the frozen snapshot");
                }
            }
            else if (Options.RequireBuiltinSnapshot)
            {
                return Failure(ConfigurationErrorCode::MissingReference,
                               Path + ".Builtin",
                               "configured carrier requires a frozen snapshot");
            }
            if (const auto ResultValue = ValidateCarrierMatch(Carrier.Match, Path + ".Match");
                !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateCarrier(Carrier, Path, Options); !ResultValue)
            {
                return ResultValue;
            }
        }
        return {};
    }

} // namespace Prism::Application::Configuration::Validation
