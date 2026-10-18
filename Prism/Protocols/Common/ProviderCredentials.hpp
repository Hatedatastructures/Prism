/**
 * @file ProviderCredentials.hpp
 * @brief 标准 provider 的冷凭据材料投影。
 */
#pragma once

#include <Prism/Account/Binding.hpp>
#include <Prism/Account/Index.hpp>
#include <Prism/Account/Materials.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace Prism::Protocols::Common
{
    class UuidCredentialCollector final
    {
    public:
        explicit UuidCredentialCollector(std::optional<std::array<std::uint8_t, 16>>& Result)
            : Result_(Result)
        {
        }

        auto operator()(
            const std::shared_ptr<const Prism::Account::AccountBinding>&,
            const Prism::Account::CredentialMaterial& Material) const -> void
        {
            if (Result_) return;
            const auto Credential = Material.Credential.View();
            if (Credential.Size() != std::array<std::uint8_t, 16>{}.size()) return;
            auto& Uuid = Result_.emplace();
            for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
            {
                Uuid[Index] = std::to_integer<std::uint8_t>(Credential.Bytes()[Index]);
            }
        }

    private:
        std::optional<std::array<std::uint8_t, 16>>& Result_;
    };

    [[nodiscard]] inline auto FirstUuidCredential(
        const Prism::Account::CredentialIndexView& Credentials)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        std::optional<std::array<std::uint8_t, 16>> Result;
        const auto Enumerated = Credentials.ForEachCredential(
            Prism::Account::CredentialKind::Uuid, UuidCredentialCollector{Result});
        if (!Enumerated) return std::nullopt;
        return Result;
    }
}
