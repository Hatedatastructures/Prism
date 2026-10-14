/** @file PolicyVersion.hpp
 * @brief 独立账户策略版本，不能作为Application配置generation使用。
 */
#pragma once
#include <cstdint>
#include <compare>
namespace Preview::Account
{
    class PolicyVersion final
    {
    public:
        constexpr PolicyVersion() noexcept = default;
        explicit constexpr PolicyVersion(const std::uint64_t Value) noexcept : Value_(Value) {}
        [[nodiscard]] constexpr auto Value() const noexcept -> std::uint64_t { return Value_; }
        explicit constexpr operator bool() const noexcept { return Value_ != 0U; }
        auto operator<=>(const PolicyVersion&) const = default;
    private:
        std::uint64_t Value_{0U};
    };
}
