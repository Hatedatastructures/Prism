/** @file Credentials.hpp @brief VMess 冷 credential trial 的 owning UUID 候选材料。 */
#pragma once
#include <Prism/Account/Credential.hpp>
#include <Prism/Account/Index.hpp>
#include <optional>
#include <vector>
namespace Prism::Vmess::Credentials
{
    [[nodiscard]] inline auto CopyUuid(const Prism::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>;

    /** @brief 冷枚举此scope的UUID材料；只返回16字节真实副本，不保存材料借用。 */
    [[nodiscard]] inline auto UuidsForScope(const Prism::Account::CredentialIndexView &Credentials)
        -> std::vector<std::array<std::uint8_t, 16>>
    {
        std::vector<std::array<std::uint8_t, 16>> Records;
        if (!Credentials)
        {
            return Records;
        }
        const auto Enumerated = Credentials.ForEachCredential(Prism::Account::CredentialKind::Uuid,
            [&Records](const std::shared_ptr<const Prism::Account::AccountBinding> &,
                       const Prism::Account::CredentialMaterial &Material)
            {
                if (const auto Uuid = CopyUuid(Material.Credential.View()))
                {
                    Records.push_back(*Uuid);
                }
            });
        if (!Enumerated)
        {
            Records.clear();
        }
        return Records;
    }

    [[nodiscard]] inline auto CopyUuid(const Prism::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        if (Credential.Kind() != Prism::Account::CredentialKind::Uuid ||
            Credential.Size() != 16U)
        {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16> Value{};
        for (std::size_t Index = 0; Index < Value.size(); ++Index)
        {
            Value[Index] = std::to_integer<std::uint8_t>(Credential.Bytes()[Index]);
        }
        return Value;
    }

}
