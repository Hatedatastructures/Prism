/**
 * @file ForwardRequestFraming.hpp
 * @brief HTTP/1.1 首请求 framing 的无状态校验工具。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <charconv>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>

namespace Prism::Http11::Detail
{
    [[nodiscard]] inline auto IsTokenChar(const char Character) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Character);
        if ((Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z') ||
            (Byte >= '0' && Byte <= '9'))
        {
            return true;
        }
        constexpr std::string_view Punctuation{"!#$%&'*+-.^_`|~"};
        return Punctuation.find(Character) != std::string_view::npos;
    }

    [[nodiscard]] inline auto IsFieldValueChar(const char Character) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Character);
        return Byte == '\t' || (Byte >= 0x20U && Byte != 0x7fU);
    }

    [[nodiscard]] inline auto IsChunkExtension(std::string_view Value) noexcept -> bool
    {
        std::size_t Offset = 0;
        while (Offset < Value.size())
        {
            while (Offset < Value.size() && (Value[Offset] == ' ' || Value[Offset] == '\t'))
            {
                ++Offset;
            }
            if (Offset == Value.size() || Value[Offset++] != ';')
            {
                return false;
            }
            while (Offset < Value.size() && (Value[Offset] == ' ' || Value[Offset] == '\t'))
            {
                ++Offset;
            }
            const auto NameStart = Offset;
            while (Offset < Value.size() && IsTokenChar(Value[Offset]))
            {
                ++Offset;
            }
            if (NameStart == Offset)
            {
                return false;
            }
            while (Offset < Value.size() && (Value[Offset] == ' ' || Value[Offset] == '\t'))
            {
                ++Offset;
            }
            if (Offset == Value.size())
            {
                continue;
            }
            if (Value[Offset++] != '=')
            {
                return false;
            }
            while (Offset < Value.size() && (Value[Offset] == ' ' || Value[Offset] == '\t'))
            {
                ++Offset;
            }
            if (Offset == Value.size())
            {
                return false;
            }
            if (Value[Offset] == '"')
            {
                ++Offset;
                bool Closed = false;
                while (Offset < Value.size())
                {
                    const auto Character = Value[Offset++];
                    if (Character == '"')
                    {
                        Closed = true;
                        break;
                    }
                    if (Character == '\\' && Offset < Value.size())
                    {
                        ++Offset;
                        continue;
                    }
                    if (!IsFieldValueChar(Character))
                    {
                        return false;
                    }
                }
                if (!Closed)
                {
                    return false;
                }
            }
            else
            {
                const auto ValueStart = Offset;
                while (Offset < Value.size() && IsTokenChar(Value[Offset]))
                {
                    ++Offset;
                }
                if (ValueStart == Offset)
                {
                    return false;
                }
            }
            while (Offset < Value.size() && (Value[Offset] == ' ' || Value[Offset] == '\t'))
            {
                ++Offset;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto IsValidTrailer(std::string_view Line) noexcept -> bool
    {
        if (Line.size() < 2U || Line.substr(Line.size() - 2U) != "\r\n")
        {
            return false;
        }
        const auto Value = Line.substr(0, Line.size() - 2U);
        const auto Colon = Value.find(':');
        if (Colon == std::string_view::npos || Colon == 0U)
        {
            return false;
        }
        for (const auto Character : Value.substr(0, Colon))
        {
            if (!IsTokenChar(Character))
            {
                return false;
            }
        }
        for (const auto Character : Value.substr(Colon + 1U))
        {
            if (!IsFieldValueChar(Character))
            {
                return false;
            }
        }
        return true;
    }

    /** @brief 解析完整 chunk-size 行并验证其扩展字段。 */
    [[nodiscard]] inline auto ParseChunkSize(
        std::span<const std::byte> Line,
        std::uint64_t &Size) noexcept -> bool
    {
        if (Line.size() < 2U)
        {
            return false;
        }
        const std::string_view Text(
            reinterpret_cast<const char *>(Line.data()), Line.size() - 2U);
        const auto Separator = Text.find(';');
        auto Digits = Text.substr(0, Separator);
        if (Separator != std::string_view::npos)
        {
            while (!Digits.empty() && (Digits.back() == ' ' || Digits.back() == '\t'))
            {
                Digits.remove_suffix(1);
            }
        }
        if (Digits.empty())
        {
            return false;
        }
        const auto [Next, ErrorValue] = std::from_chars(
            Digits.data(), Digits.data() + Digits.size(), Size, 16);
        return ErrorValue == std::errc{} && Next == Digits.data() + Digits.size() &&
               (Separator == std::string_view::npos ||
               IsChunkExtension(Text.substr(Separator)));
    }

    [[nodiscard]] inline auto ToBodyEndFailure(Prism::Fault::Failure Failure)
        -> Prism::Fault::Failure
    {
        if (Failure.Succeeded() || Failure.Code == Prism::Fault::Code::Eof)
        {
            return Prism::Fault::FromNative(
                Prism::make_error_code(Prism::Error::UnexpectedEof));
        }
        return Failure;
    }

    [[nodiscard]] inline auto ParseUpgradeStatus(std::string_view Header) noexcept
        -> std::optional<int>
    {
        if (!Header.starts_with("HTTP/"))
        {
            return std::nullopt;
        }
        const auto LineEnd = Header.find("\r\n");
        const auto Space = Header.find(' ');
        if (LineEnd == std::string_view::npos || Space == std::string_view::npos ||
            Space + 4U > LineEnd)
        {
            return std::nullopt;
        }
        const auto CodeText = Header.substr(Space + 1U, 3U);
        if (CodeText.size() != 3U || (CodeText[0] < '0' || CodeText[0] > '9') ||
            (CodeText[1] < '0' || CodeText[1] > '9') ||
            (CodeText[2] < '0' || CodeText[2] > '9') ||
            (Space + 4U < LineEnd && Header[Space + 4U] != ' '))
        {
            return std::nullopt;
        }
        return (CodeText[0] - '0') * 100 + (CodeText[1] - '0') * 10 + (CodeText[2] - '0');
    }

    enum class ChunkState : std::uint8_t
    {
        SizeLine,
        Data,
        DataCrlf,
        Trailer,
        Done,
    };
} // namespace Prism::Http11::Detail
