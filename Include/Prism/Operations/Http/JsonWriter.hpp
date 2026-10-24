/** @file JsonWriter.hpp @brief 只负责预算内 JSON 文本和精确转义的拥有型 writer。 */
#pragma once
#include <Prism/Operations/Http/Limits.hpp>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
namespace Prism::Operations::HttpDetail
{
    class JsonWriter final
    {
    public:
        explicit JsonWriter(const std::size_t Limit = MaxResponseBytes);

        [[nodiscard]] auto Append(const std::string_view Value) -> bool;

        [[nodiscard]] auto String(const std::string_view Value) -> bool;

        [[nodiscard]] auto Key(const std::string_view Name) -> bool;

        [[nodiscard]] auto Unsigned(const std::uint64_t Value) -> bool;

        [[nodiscard]] auto Boolean(const bool Value) -> bool;
        /** @brief 64 位身份、计数和时间的精确十进制字符串，避免浏览器浮点精度损失。 */
        [[nodiscard]] auto Decimal(const std::uint64_t Value) -> bool;

        [[nodiscard]] auto Null() -> bool;

        [[nodiscard]] auto Good() const noexcept -> bool
        {
            return !Failed_;
        }

        [[nodiscard]] auto Take() && -> std::string;

    private:
        std::string Value_;
        std::size_t Limit_;
        bool Failed_{false};
    };

}
