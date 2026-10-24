/** @file JsonWriter.cpp @brief 有界 JSON 文本写入实现。 */
#include <Prism/Operations/Http/JsonWriter.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>
#include <utility>

namespace Prism::Operations::HttpDetail
{
    JsonWriter::JsonWriter(const std::size_t Limit) : Limit_(Limit)
    {
        Value_.reserve(std::min<std::size_t>(Limit_, 4096U));
    }

    auto JsonWriter::Append(const std::string_view Value) -> bool
    {
        if (Value.size() > Limit_ - std::min(Value_.size(), Limit_))
        {
            Failed_ = true;
            return false;
        }
        Value_.append(Value);
        return true;
    }

    auto JsonWriter::String(const std::string_view Value) -> bool
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

    auto JsonWriter::Key(const std::string_view Name) -> bool
    {
        return String(Name) && Append(":");
    }

    auto JsonWriter::Unsigned(const std::uint64_t Value) -> bool
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

    auto JsonWriter::Boolean(const bool Value) -> bool
    {
        if (Value) return Append("true");
        return Append("false");
    }

    auto JsonWriter::Decimal(const std::uint64_t Value) -> bool
    {
        return Append("\"") && Unsigned(Value) && Append("\"");
    }

    auto JsonWriter::Null() -> bool
    {
        return Append("null");
    }

    auto JsonWriter::Take() && -> std::string
    {
        return std::move(Value_);
    }
}
