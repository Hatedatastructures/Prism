/**
 * @file UuidCredentialSelection.hpp
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
        explicit UuidCredentialCollector(
            std::optional<std::array<std::uint8_t, 16>>& Result);

        auto operator()(
            const std::shared_ptr<const Prism::Account::AccountBinding>&,
            const Prism::Account::CredentialMaterial& Material) const -> void;

    private:
        std::optional<std::array<std::uint8_t, 16>>& Result_;
    };

    [[nodiscard]] auto FirstUuidCredential(
        const Prism::Account::CredentialIndexView& Credentials)
        -> std::optional<std::array<std::uint8_t, 16>>;
}
