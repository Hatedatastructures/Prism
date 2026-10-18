/**
 * @file ReloadJson.hpp
 * @brief 解析唯一的受限 Reload JSON envelope。
 */
#pragma once

#include <Prism/Operations/Http/Limits.hpp>
#include <Prism/Operations/Models.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>

namespace Prism::Operations
{

    struct ReloadDocument final
    {
        ReloadMode Mode{ReloadMode::ValidateOnly};
        Prism::GenerationId BaseGeneration{};
        std::string ConfigurationJson;
    };

    enum class ReloadDocumentError : std::uint8_t
    {
        Malformed,
        Oversized,
    };

    namespace ReloadJsonDetail
    {

        [[nodiscard]] inline auto IsWhitespace(const char Value) noexcept -> bool
        {
            return Value == ' ' || Value == '\t' || Value == '\r' || Value == '\n';
        }

        inline auto SkipWhitespace(const std::string_view Input, std::size_t &Offset) noexcept -> void
        {
            while (Offset < Input.size() && IsWhitespace(Input[Offset]))
            {
                ++Offset;
            }
        }

        [[nodiscard]] inline auto ParseString(const std::string_view Input, std::size_t &Offset,
                                               std::string &Output) -> bool
        {
            if (Offset >= Input.size() || Input[Offset] != '"')
            {
                return false;
            }
            ++Offset;
            Output.clear();
            while (Offset < Input.size())
            {
                const auto Character = static_cast<unsigned char>(Input[Offset++]);
                if (Character == '"')
                {
                    return true;
                }
                if (Character < 0x20U)
                {
                    return false;
                }
                if (Character != '\\')
                {
                    Output.push_back(static_cast<char>(Character));
                    continue;
                }
                if (Offset >= Input.size())
                {
                    return false;
                }
                const char Escaped = Input[Offset++];
                if (Escaped == '"' || Escaped == '\\' || Escaped == '/')
                {
                    Output.push_back(Escaped);
                }
                else if (Escaped == 'b') Output.push_back('\b');
                else if (Escaped == 'f') Output.push_back('\f');
                else if (Escaped == 'n') Output.push_back('\n');
                else if (Escaped == 'r') Output.push_back('\r');
                else if (Escaped == 't') Output.push_back('\t');
                else if (Escaped == 'u')
                {
                    if (Input.size() - Offset < 4U)
                    {
                        return false;
                    }
                    std::uint32_t Codepoint{};
                    for (std::size_t Index = 0; Index < 4U; ++Index)
                    {
                        const char Digit = Input[Offset++];
                        std::uint32_t Value{};
                        if (Digit >= '0' && Digit <= '9') Value = static_cast<std::uint32_t>(Digit - '0');
                        else if (Digit >= 'a' && Digit <= 'f') Value = static_cast<std::uint32_t>(Digit - 'a' + 10);
                        else if (Digit >= 'A' && Digit <= 'F') Value = static_cast<std::uint32_t>(Digit - 'A' + 10);
                        else return false;
                        Codepoint = (Codepoint << 4U) | Value;
                    }
                    if (Codepoint > 0x7fU)
                    {
                        return false;
                    }
                    Output.push_back(static_cast<char>(Codepoint));
                }
                else
                {
                    return false;
                }
            }
            return false;
        }

        [[nodiscard]] inline auto SkipValue(const std::string_view Input, std::size_t &Offset,
                                             const char RequiredOpening) -> bool
        {
            if (Offset >= Input.size() || Input[Offset] != RequiredOpening)
            {
                return false;
            }
            std::array<char, 64> Closers{};
            std::size_t Depth = 0U;
            bool InString = false;
            bool Escaped = false;
            for (; Offset < Input.size(); ++Offset)
            {
                const char Character = Input[Offset];
                if (InString)
                {
                    if (Escaped)
                    {
                        Escaped = false;
                    }
                    else if (Character == '\\')
                    {
                        Escaped = true;
                    }
                    else if (Character == '"')
                    {
                        InString = false;
                    }
                    else if (static_cast<unsigned char>(Character) < 0x20U)
                    {
                        return false;
                    }
                    continue;
                }
                if (Character == '"')
                {
                    InString = true;
                    continue;
                }
                if (Character == '{' || Character == '[')
                {
                    if (Depth == Closers.size())
                    {
                        return false;
                    }
                    Closers[Depth++] = Character == '{' ? '}' : ']';
                    continue;
                }
                if (Character == '}' || Character == ']')
                {
                    if (Depth == 0U || Closers[Depth - 1U] != Character)
                    {
                        return false;
                    }
                    --Depth;
                    if (Depth == 0U)
                    {
                        ++Offset;
                        return true;
                    }
                }
            }
            return false;
        }

        [[nodiscard]] inline auto ParseBaseGeneration(const std::string_view Text,
                                                       Prism::GenerationId &Generation) -> bool
        {
            if (Text.empty())
            {
                return false;
            }
            std::uint64_t Value{};
            const auto [End, Error] = std::from_chars(Text.data(), Text.data() + Text.size(), Value, 10);
            if (Error != std::errc{} || End != Text.data() + Text.size() || Value == 0U)
            {
                return false;
            }
            Generation = Prism::GenerationId{Value};
            return true;
        }

    } // namespace ReloadJsonDetail

    /** @brief 解析 mode/base_generation/configuration；重复或未知顶层键一律拒绝。 */
    [[nodiscard]] inline auto ParseReloadDocument(const std::string_view Json)
        -> std::expected<ReloadDocument, ReloadDocumentError>
    {
        if (Json.size() > MaxReloadBodyBytes)
        {
            return std::unexpected(ReloadDocumentError::Oversized);
        }
        std::size_t Offset = 0U;
        ReloadJsonDetail::SkipWhitespace(Json, Offset);
        if (Offset >= Json.size() || Json[Offset++] != '{')
        {
            return std::unexpected(ReloadDocumentError::Malformed);
        }
        ReloadDocument Result;
        bool ModeSeen = false;
        bool BaseSeen = false;
        bool ConfigurationSeen = false;
        bool First = true;
        while (true)
        {
            ReloadJsonDetail::SkipWhitespace(Json, Offset);
            if (Offset < Json.size() && Json[Offset] == '}')
            {
                ++Offset;
                break;
            }
            if (!First)
            {
                if (Offset >= Json.size() || Json[Offset++] != ',')
                {
                    return std::unexpected(ReloadDocumentError::Malformed);
                }
                ReloadJsonDetail::SkipWhitespace(Json, Offset);
            }
            First = false;
            std::string Key;
            if (!ReloadJsonDetail::ParseString(Json, Offset, Key))
            {
                return std::unexpected(ReloadDocumentError::Malformed);
            }
            ReloadJsonDetail::SkipWhitespace(Json, Offset);
            if (Offset >= Json.size() || Json[Offset++] != ':')
            {
                return std::unexpected(ReloadDocumentError::Malformed);
            }
            ReloadJsonDetail::SkipWhitespace(Json, Offset);
            if (Key == "mode")
            {
                if (ModeSeen)
                {
                    return std::unexpected(ReloadDocumentError::Malformed);
                }
                ModeSeen = true;
                std::string Mode;
                if (!ReloadJsonDetail::ParseString(Json, Offset, Mode))
                {
                    return std::unexpected(ReloadDocumentError::Malformed);
                }
                if (Mode == "validate_only") Result.Mode = ReloadMode::ValidateOnly;
                else if (Mode == "apply") Result.Mode = ReloadMode::Apply;
                else if (Mode == "apply_and_persist") Result.Mode = ReloadMode::ApplyAndPersist;
                else return std::unexpected(ReloadDocumentError::Malformed);
            }
            else if (Key == "base_generation")
            {
                if (BaseSeen)
                {
                    return std::unexpected(ReloadDocumentError::Malformed);
                }
                BaseSeen = true;
                std::string Base;
                if (!ReloadJsonDetail::ParseString(Json, Offset, Base) ||
                    !ReloadJsonDetail::ParseBaseGeneration(Base, Result.BaseGeneration))
                {
                    return std::unexpected(ReloadDocumentError::Malformed);
                }
            }
            else if (Key == "configuration")
            {
                if (ConfigurationSeen)
                {
                    return std::unexpected(ReloadDocumentError::Malformed);
                }
                ConfigurationSeen = true;
                const auto Begin = Offset;
                if (!ReloadJsonDetail::SkipValue(Json, Offset, '{'))
                {
                    return std::unexpected(ReloadDocumentError::Malformed);
                }
                Result.ConfigurationJson.assign(Json.substr(Begin, Offset - Begin));
            }
            else
            {
                return std::unexpected(ReloadDocumentError::Malformed);
            }
            ReloadJsonDetail::SkipWhitespace(Json, Offset);
            if (Offset < Json.size() && Json[Offset] == '}')
            {
                ++Offset;
                break;
            }
            if (Offset >= Json.size() || Json[Offset] != ',')
            {
                return std::unexpected(ReloadDocumentError::Malformed);
            }
        }
        ReloadJsonDetail::SkipWhitespace(Json, Offset);
        if (Offset != Json.size() || !ModeSeen || !BaseSeen || !ConfigurationSeen)
        {
            return std::unexpected(ReloadDocumentError::Malformed);
        }
        return Result;
    }

} // namespace Prism::Operations
