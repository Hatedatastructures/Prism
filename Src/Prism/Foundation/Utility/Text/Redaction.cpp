/** @file Redaction.cpp
 * @brief 中立文本字段和 Bearer 凭据识别实现。
 */
#include <Prism/Foundation/Utility/Text/Redaction.hpp>

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace Prism::Text
{
    StringWriter::StringWriter(std::string& Output) noexcept
        : Output_(Output)
    {
    }

    auto StringWriter::Append(const std::string_view Value) -> void
    {
        Output_.append(Value);
    }

    auto StringWriter::PushBack(const char Value) -> void
    {
        Output_.push_back(Value);
    }

    auto BoundedText::PushBack(const char Value) noexcept -> void
    {
        if (Size_ < Output_.size()) { Output_[Size_++] = Value; }
        else { Truncated_ = true; }
    }

    auto BoundedText::Append(const std::string_view Value) noexcept -> void
    {
        for (const auto Character : Value) { PushBack(Character); }
    }

    auto BoundedText::operator+=(const std::string_view Value) noexcept -> BoundedText&
    {
        Append(Value);
        return *this;
    }

    auto IsFieldNameCharacter(const char Value) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Value);
        return (Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z') ||
            (Byte >= '0' && Byte <= '9') || Value == '_' || Value == '-';
    }

    auto EqualsInsensitive(const std::string_view Left,
        const std::string_view Right) noexcept -> bool
    {
        if (Left.size() != Right.size())
        {
            return false;
        }
        for (std::size_t Index = 0U; Index < Left.size(); ++Index)
        {
            auto A = static_cast<unsigned char>(Left[Index]);
            auto B = static_cast<unsigned char>(Right[Index]);
            if (A >= 'A' && A <= 'Z') { A += 'a' - 'A'; }
            if (B >= 'A' && B <= 'Z') { B += 'a' - 'A'; }
            if (A != B) { return false; }
        }
        return true;
    }

    auto IsSensitiveField(const std::string_view Name) noexcept -> bool
    {
        constexpr std::string_view Names[]{"password", "passwd", "token", "secret", "psk",
            "credential", "credentials", "authorization", "private_key", "private-key", "key",
            "access_token", "access-token", "refresh_token", "refresh-token", "api_key", "api-key",
            "client_secret", "client-secret", "secret_key", "secret-key"};
        for (const auto Expected : Names)
        {
            if (EqualsInsensitive(Name, Expected))
            {
                return true;
            }
        }
        return false;
    }

    auto IsAuthorizationField(const std::string_view Name) noexcept -> bool
    {
        return EqualsInsensitive(Name, "authorization");
    }

    auto IsBearerScheme(const std::string_view Value) noexcept -> bool
    {
        if (Value.size() < 6U ||
            (Value.size() > 6U &&
             std::isspace(static_cast<unsigned char>(Value[6])) == 0))
        {
            return false;
        }
        return EqualsInsensitive(Value.substr(0U, 6U), "bearer");
    }

    auto LooksLikeAssignment(const std::string_view Input,
        std::size_t Position) noexcept -> bool
    {
        while (Position < Input.size() &&
               std::isspace(static_cast<unsigned char>(Input[Position])) != 0)
        {
            ++Position;
        }
        const auto NameStart = Position;
        while (Position < Input.size() && IsFieldNameCharacter(Input[Position]))
        {
            ++Position;
        }
        return Position > NameStart && Position < Input.size() &&
               (Input[Position] == '=' || Input[Position] == ':');
    }

    auto RedactSensitiveText(const std::string_view Input) -> std::string
    {
        std::string Output;
        Output.reserve(Input.size());
        StringWriter Writer(Output);
        AppendRedactedText(Input, Writer);
        return Output;
    }
}
