/**
 * @file SecretRefResolver.hpp
 * @brief SecretRef 的显式解析边界。
 */

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Application::Configuration
{

    class SecretResolutionTransaction;

    class SecretRefResolver final
    {
    public:
        using Callback = std::function<std::optional<std::string>(std::string_view)>;

        SecretRefResolver() = default;

        explicit SecretRefResolver(Callback Resolver) : Resolver_(std::move(Resolver))
        {
        }

        [[nodiscard]] auto Resolve(std::string_view Reference) const
            -> std::optional<std::string>
        {
            if (!Resolver_)
            {
                return std::nullopt;
            }
            return Resolver_(Reference);
        }

        [[nodiscard]] auto operator()(std::string_view Reference) const
            -> std::optional<std::string>
        {
            return Resolve(Reference);
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return static_cast<bool>(Resolver_);
        }

        [[nodiscard]] auto CallbackValue() const -> Callback
        {
            return Resolver_;
        }

        [[nodiscard]] auto TakeCallbackValue() && -> Callback
        {
            return std::move(Resolver_);
        }

    private:
        Callback Resolver_;
    };

    using SecretResolver = SecretRefResolver;

    class MapSecretRefResolver final
    {
    public:
        explicit MapSecretRefResolver(std::map<std::string, std::string> Values);

        [[nodiscard]] auto Resolve(std::string_view Reference) const
            -> std::optional<std::string>;
        [[nodiscard]] auto CallbackValue() const -> SecretRefResolver::Callback;

    private:
        std::shared_ptr<SecretResolutionTransaction> Resolution_;
    };

    /** @brief 构造内联配置密钥优先、外部回调兜底的解析器。 */
    [[nodiscard]] auto MakeChainedSecretResolver(
        std::map<std::string, std::string> InlineValues,
        SecretRefResolver::Callback Fallback = {}) -> SecretRefResolver::Callback;

} // namespace Preview::Application::Configuration
