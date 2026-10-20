/** @file Credentials.hpp @brief VMess 冷 credential trial 的 owning UUID 候选材料。 */
#pragma once
#include <Prism/Account/Credential.hpp>
#include <Prism/Account/Index.hpp>
#include <optional>
#include <vector>
#include <array>
#include <cstddef>
#include <cstdint>
namespace Prism::Vmess::Credentials
{
    [[nodiscard]] auto CopyUuid(const Prism::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>;

    /** @brief 冷枚举此scope的UUID材料；只返回16字节真实副本，不保存材料借用。 */
    [[nodiscard]] auto UuidsForScope(const Prism::Account::CredentialIndexView &Credentials)
        -> std::vector<std::array<std::uint8_t, 16>>;

}
