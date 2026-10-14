/** @file Credentials.hpp @brief VMess 冷 credential trial 的 owning UUID 候选材料。 */
#pragma once
#include <Preview/Account/Credential.hpp>
#include <Preview/Account/Index.hpp>
#include <optional>
#include <vector>
namespace Preview::Vmess::Credentials
{
    [[nodiscard]] inline auto CopyUuid(const Preview::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>;

    /** @brief 冷枚举此scope的UUID材料；只返回16字节真实副本，不保存材料借用。 */
    [[nodiscard]] inline auto UuidsForScope(const Preview::Account::CredentialIndexView &Credentials)
        -> std::vector<std::array<std::uint8_t, 16>>
    {
        std::vector<std::array<std::uint8_t, 16>> Records;
        if (!Credentials)
        {
            return Records;
        }
        const auto Enumerated = Credentials.ForEachCredential(Preview::Account::CredentialKind::Uuid,
            [&Records](const std::shared_ptr<const Preview::Account::AccountBinding> &,
                       const Preview::Account::CredentialMaterial &Material)
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

    [[nodiscard]] inline auto CopyUuid(const Preview::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        if (Credential.Kind() != Preview::Account::CredentialKind::Uuid ||
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
