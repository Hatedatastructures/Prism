/**
 * @file Redaction.hpp
 * @brief 统计详情的边界脱敏。
 */

#pragma once

#include <cctype>
#include <string>
#include <string_view>

namespace Preview::Statistics
{

    [[nodiscard]] inline auto IsFieldNameCharacter(const char Value) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Value);
        return std::isalnum(Byte) != 0 || Value == '_' || Value == '-';
    }

    [[nodiscard]] inline auto IsSensitiveField(std::string_view Name) noexcept -> bool
    {
        std::string Lower;
        Lower.reserve(Name.size());
        for (const char Value : Name)
        {
            Lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(Value))));
        }
        return Lower == "password" || Lower == "passwd" || Lower == "token" ||
               Lower == "secret" || Lower == "psk" || Lower == "credential" ||
               Lower == "credentials" || Lower == "authorization" || Lower == "private_key" ||
               Lower == "private-key" || Lower == "key" || Lower == "access_token" ||
               Lower == "access-token" || Lower == "refresh_token" || Lower == "refresh-token" ||
               Lower == "api_key" || Lower == "api-key" || Lower == "client_secret" ||
               Lower == "client-secret" || Lower == "secret_key" || Lower == "secret-key";
    }

    [[nodiscard]] inline auto IsAuthorizationField(std::string_view Name) noexcept -> bool
    {
        if (Name.size() != 13U)
        {
            return false;
        }
        constexpr std::string_view Expected{"authorization"};
        for (std::size_t Index = 0; Index < Expected.size(); ++Index)
        {
            if (std::tolower(static_cast<unsigned char>(Name[Index])) !=
                std::tolower(static_cast<unsigned char>(Expected[Index])))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto IsBearerScheme(const std::string_view Value) noexcept -> bool
    {
        if (Value.size() < 6U ||
            (Value.size() > 6U &&
             std::isspace(static_cast<unsigned char>(Value[6])) == 0))
        {
            return false;
        }
        constexpr std::string_view Expected{"bearer"};
        for (std::size_t Index = 0; Index < Expected.size(); ++Index)
        {
            if (std::tolower(static_cast<unsigned char>(Value[Index])) !=
                std::tolower(static_cast<unsigned char>(Expected[Index])))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto LooksLikeAssignment(const std::string_view Input,
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

    /**
     * @brief 脱敏常见 key=value、key:value 和 JSON 风格的敏感字段。
     */
    [[nodiscard]] inline auto RedactSensitiveText(std::string_view Input) -> std::string
    {
        std::string Output;
        Output.reserve(Input.size());

        std::size_t Index = 0;
        while (Index < Input.size())
        {
            const bool Boundary = Index == 0 || !IsFieldNameCharacter(Input[Index - 1]);
            if (!Boundary || !IsFieldNameCharacter(Input[Index]))
            {
                Output.push_back(Input[Index++]);
                continue;
            }

            const auto NameStart = Index;
            while (Index < Input.size() && IsFieldNameCharacter(Input[Index]))
            {
                ++Index;
            }
            const auto NameEnd = Index;
            const auto Name = Input.substr(NameStart, NameEnd - NameStart);

            auto Probe = NameEnd;
            if (Probe < Input.size() && (Input[Probe] == '"' || Input[Probe] == '\''))
            {
                ++Probe;
            }
            while (Probe < Input.size() && std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
            {
                ++Probe;
            }
            if (Probe >= Input.size() || (Input[Probe] != '=' && Input[Probe] != ':') ||
                !IsSensitiveField(Name))
            {
                Output.append(Input.substr(NameStart, NameEnd - NameStart));
                continue;
            }

            const char Separator = Input[Probe];
            Output.append(Input.substr(NameStart, Probe - NameStart + 1));
            ++Probe;
            while (Probe < Input.size() && std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
            {
                Output.push_back(Input[Probe++]);
            }

            if ((Separator == ':' || Separator == '=') && IsAuthorizationField(Name) &&
                Probe < Input.size() && IsBearerScheme(Input.substr(Probe)))
            {
                if (Separator == ':')
                {
                    Output.append(Input.substr(Probe, 6U));
                    Probe += 6U;
                    while (Probe < Input.size() &&
                           std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
                    {
                        Output.push_back(Input[Probe++]);
                    }
                    Output += "<redacted>";
                    while (Probe < Input.size() &&
                           !std::isspace(static_cast<unsigned char>(Input[Probe])) &&
                           Input[Probe] != ',' && Input[Probe] != '}' && Input[Probe] != ']')
                    {
                        ++Probe;
                    }
                }
                else
                {
                    Output += "<redacted>";
                    Probe += 6U;
                    const auto NextField = Probe;
                    while (Probe < Input.size() &&
                           std::isspace(static_cast<unsigned char>(Input[Probe])) != 0)
                    {
                        ++Probe;
                    }
                    if (LooksLikeAssignment(Input, Probe))
                    {
                        Probe = NextField;
                    }
                    else
                    {
                        while (Probe < Input.size() &&
                               !std::isspace(static_cast<unsigned char>(Input[Probe])) &&
                               Input[Probe] != ',' && Input[Probe] != '}' && Input[Probe] != ']')
                        {
                            ++Probe;
                        }
                    }
                }
                Index = Probe;
                continue;
            }

            if (Probe < Input.size() && (Input[Probe] == '"' || Input[Probe] == '\''))
            {
                const char Quote = Input[Probe++];
                Output.push_back(Quote);
                Output += "<redacted>";
                while (Probe < Input.size() && Input[Probe] != Quote)
                {
                    ++Probe;
                }
                if (Probe < Input.size())
                {
                    Output.push_back(Input[Probe++]);
                }
            }
            else
            {
                Output += "<redacted>";
                while (Probe < Input.size() && !std::isspace(static_cast<unsigned char>(Input[Probe])) &&
                       Input[Probe] != ',' && Input[Probe] != '}' && Input[Probe] != ']')
                {
                    ++Probe;
                }
            }
            Index = Probe;
        }
        return Output;
    }

} // namespace Preview::Statistics
