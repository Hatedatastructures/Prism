/** @file CredentialScope.hpp
 * @brief 冷注册的凭据域身份；热路径不解析协议或 realm 名称。
 */
#pragma once
#include <cstdint>
#include <compare>
namespace Prism::Account
{
    class CredentialScope final
    {
    public:
        constexpr CredentialScope() noexcept = default;
        explicit constexpr CredentialScope(const std::uint32_t Value) noexcept : Value_(Value) {}
        [[nodiscard]] constexpr auto Value() const noexcept -> std::uint32_t { return Value_; }
        explicit constexpr operator bool() const noexcept { return Value_ != 0U; }
        auto operator<=>(const CredentialScope&) const = default;
    private:
        std::uint32_t Value_{0U};
    };
}
