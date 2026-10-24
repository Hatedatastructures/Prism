/** @file UuidCredentialSelection.cpp @brief UUID 凭据材料投影实现。 */

#include <Prism/Protocols/Common/UuidCredentialSelection.hpp>

namespace Prism::Protocols::Common
{
    UuidCredentialCollector::UuidCredentialCollector(
        std::optional<std::array<std::uint8_t, 16>>& Result)
        : Result_(Result)
    {
    }

    auto UuidCredentialCollector::operator()(
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

    [[nodiscard]] auto FirstUuidCredential(
        const Prism::Account::CredentialIndexView& Credentials)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        std::optional<std::array<std::uint8_t, 16>> Result;
        const auto Enumerated = Credentials.ForEachCredential(
            Prism::Account::CredentialKind::Uuid, UuidCredentialCollector{Result});
        if (!Enumerated) return std::nullopt;
        return Result;
    }
} // namespace Prism::Protocols::Common
