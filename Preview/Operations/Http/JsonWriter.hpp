/** @file JsonWriter.hpp @brief 只负责预算内 JSON 文本和精确转义的拥有型 writer。 */
#pragma once
#include <Preview/Operations/Http/Limits.hpp>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
namespace Preview::Operations::HttpDetail
{
    class JsonWriter final
    {
    public:
        explicit JsonWriter(const std::size_t Limit = MaxResponseBytes) : Limit_(Limit)
        {
            Value_.reserve(std::min<std::size_t>(Limit_, 4096U));
        }

        [[nodiscard]] auto Append(const std::string_view Value) -> bool
        {
            if (Value.size() > Limit_ - std::min(Value_.size(), Limit_))
            {
                Failed_ = true;
                return false;
            }
            Value_.append(Value);
            return true;
        }

        [[nodiscard]] auto String(const std::string_view Value) -> bool
        {
            if (!Append("\""))
            {
                return false;
            }
            for (const auto Character : Value)
            {
                switch (Character)
                {
                case '"':
                    if (!Append("\\\""))
                    {
                        return false;
                    }
                    break;
                case '\\':
                    if (!Append("\\\\"))
                    {
                        return false;
                    }
                    break;
                case '\b':
                    if (!Append("\\b"))
                    {
                        return false;
                    }
                    break;
                case '\f':
                    if (!Append("\\f"))
                    {
                        return false;
                    }
                    break;
                case '\n':
                    if (!Append("\\n"))
                    {
                        return false;
                    }
                    break;
                case '\r':
                    if (!Append("\\r"))
                    {
                        return false;
                    }
                    break;
                case '\t':
                    if (!Append("\\t"))
                    {
                        return false;
                    }
                    break;
                default:
                    if (static_cast<unsigned char>(Character) < 0x20U)
                    {
                        constexpr std::array<char, 16> Hex{
                            '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
                        std::array<char, 6> Escaped{'\\', 'u', '0', '0', '0', '0'};
                        const auto Byte = static_cast<unsigned char>(Character);
                        Escaped[4] = Hex[(Byte >> 4U) & 0x0fU];
                        Escaped[5] = Hex[Byte & 0x0fU];
                        if (!Append(std::string_view(Escaped.data(), Escaped.size())))
                        {
                            return false;
                        }
                    }
                    else if (!Append(std::string_view(&Character, 1)))
                    {
                        return false;
                    }
                    break;
                }
            }
            return Append("\"");
        }

        [[nodiscard]] auto Key(const std::string_view Name) -> bool
        {
            return String(Name) && Append(":");
        }

        [[nodiscard]] auto Unsigned(const std::uint64_t Value) -> bool
        {
            std::array<char, 32> Buffer{};
            const auto [End, Error] = std::to_chars(Buffer.data(), Buffer.data() + Buffer.size(), Value);
            if (Error != std::errc{})
            {
                Failed_ = true;
                return false;
            }
            return Append(std::string_view(Buffer.data(), static_cast<std::size_t>(End - Buffer.data())));
        }

        [[nodiscard]] auto Boolean(const bool Value) -> bool
        {
            if (Value) return Append("true");
            return Append("false");
        }
        /** @brief 64 位身份、计数和时间的精确十进制字符串，避免浏览器浮点精度损失。 */
        [[nodiscard]] auto Decimal(const std::uint64_t Value) -> bool
        { return Append("\"") && Unsigned(Value) && Append("\""); }

        [[nodiscard]] auto Null() -> bool
        {
            return Append("null");
        }

        [[nodiscard]] auto Good() const noexcept -> bool
        {
            return !Failed_;
        }

        [[nodiscard]] auto Take() && -> std::string
        {
            return std::move(Value_);
        }

    private:
        std::string Value_;
        std::size_t Limit_;
        bool Failed_{false};
    };

}
