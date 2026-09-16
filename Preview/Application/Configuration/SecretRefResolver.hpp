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

    private:
        Callback Resolver_;
    };

    using SecretResolver = SecretRefResolver;

    class MapSecretRefResolver final
    {
    public:
        explicit MapSecretRefResolver(std::map<std::string, std::string> Values)
            : Values_(std::make_shared<const std::map<std::string, std::string>>(std::move(Values)))
        {
        }

        [[nodiscard]] auto Resolve(std::string_view Reference) const
            -> std::optional<std::string>
        {
            const auto It = Values_->find(std::string(Reference));
            if (It == Values_->end() || It->second.empty())
            {
                return std::nullopt;
            }
            return It->second;
        }

        [[nodiscard]] auto CallbackValue() const -> SecretRefResolver::Callback
        {
            const auto Values = Values_;
            return [Values](std::string_view Reference) -> std::optional<std::string>
            {
                const auto It = Values->find(std::string(Reference));
                if (It == Values->end() || It->second.empty())
                {
                    return std::nullopt;
                }
                return It->second;
            };
        }

    private:
        std::shared_ptr<const std::map<std::string, std::string>> Values_;
    };

} // namespace Preview::Application::Configuration
