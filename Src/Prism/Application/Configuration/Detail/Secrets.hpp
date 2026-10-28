/** @file Secrets.hpp @brief 配置 secrets 解析事务与明文擦除器私有实现声明。 */
#pragma once

#include <Prism/Account/SecureBytes.hpp>
#include <Prism/Application/Configuration/ResolvedSecrets.hpp>
#include <Prism/Application/Configuration/SecretRefResolver.hpp>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Application::Configuration::Detail
{

    class SensitiveStringWiper final
    {
    public:
        explicit SensitiveStringWiper(std::string &Value) noexcept;
        ~SensitiveStringWiper();

        SensitiveStringWiper(const SensitiveStringWiper &) = delete;
        auto operator=(const SensitiveStringWiper &) -> SensitiveStringWiper & = delete;

    private:
        std::string *Value_;
    };

    class SensitiveStringMapWiper final
    {
    public:
        explicit SensitiveStringMapWiper(std::map<std::string, std::string> &Values) noexcept;
        ~SensitiveStringMapWiper();

        SensitiveStringMapWiper(const SensitiveStringMapWiper &) = delete;
        auto operator=(const SensitiveStringMapWiper &) -> SensitiveStringMapWiper & = delete;

        auto Release() noexcept -> void;

    private:
        std::map<std::string, std::string> *Values_;
    };

    class SecretResolutionTransaction final
    {
    public:
        SecretResolutionTransaction(std::map<std::string, std::string> &&InlineValues,
                                    SecretRefResolver::Callback ExternalResolver);
        SecretResolutionTransaction(const std::map<std::string, std::string> &InlineValues,
                                    SecretRefResolver::Callback ExternalResolver);
        ~SecretResolutionTransaction();

        SecretResolutionTransaction(const SecretResolutionTransaction &) = delete;
        auto operator=(const SecretResolutionTransaction &) -> SecretResolutionTransaction & = delete;
        SecretResolutionTransaction(SecretResolutionTransaction &&) = delete;
        auto operator=(SecretResolutionTransaction &&) -> SecretResolutionTransaction & = delete;

        [[nodiscard]] auto Resolve(std::string_view Reference) -> ResolvedSecrets::View;
        [[nodiscard]] auto Lookup(std::string_view Reference) const -> ResolvedSecrets::View;
        auto Seal() noexcept -> void;
        [[nodiscard]] auto TakeResolvedSecrets() -> std::unique_ptr<ResolvedSecrets>;

    private:
        std::map<std::string, Prism::Account::SecureBytes> InlineValues_;
        std::map<std::string, std::optional<Prism::Account::SecureBytes>> Resolved_;
        SecretRefResolver::Callback ExternalResolver_;
        bool Sealed_{false};
    };

} // namespace Prism::Application::Configuration::Detail
