/**
 * @file ProtocolIndependentValidation.hpp
 * @brief 与具体 builtin 无关的协议字段和网络文本规则。
 */
#pragma once

#include <Prism/Application/Configuration/Validation/CommonValidation.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Application::Configuration::Validation
{

    [[nodiscard]] inline auto IsMuxMode(const std::string_view Mode) noexcept -> bool
    {
        return Mode == "Smux" || Mode == "Yamux" || Mode == "H2Mux";
    }

    [[nodiscard]] inline auto IsTrustTunnelNetwork(const std::string_view Network) noexcept -> bool
    {
        return Network == "Tcp" || Network == "Udp" || Network == "Both";
    }

    [[nodiscard]] inline auto IsXhttpMode(const std::string_view Mode) noexcept -> bool
    {
        return Mode == "StreamOne" || Mode == "StreamUp" || Mode == "PacketUp";
    }

    [[nodiscard]] inline auto IsValidUuidText(const std::string_view Value) noexcept -> bool
    {
        std::size_t Bytes = 0;
        int High = -1;
        for (const char Character : Value)
        {
            if (Character == '-')
            {
                continue;
            }
            const auto Digit = [](const char Value) noexcept -> int
            {
                if (Value >= '0' && Value <= '9') return Value - '0';
                if (Value >= 'a' && Value <= 'f') return Value - 'a' + 10;
                if (Value >= 'A' && Value <= 'F') return Value - 'A' + 10;
                return -1;
            }(Character);
            if (Digit < 0)
            {
                return false;
            }
            if (High < 0)
            {
                High = Digit;
            }
            else
            {
                ++Bytes;
                High = -1;
            }
        }
        return Bytes == 16U && High < 0;
    }

    [[nodiscard]] inline auto IsAsciiAlphaNumeric(const char Character) noexcept -> bool
    {
        return (Character >= 'a' && Character <= 'z') ||
               (Character >= 'A' && Character <= 'Z') ||
               (Character >= '0' && Character <= '9');
    }

    [[nodiscard]] inline auto IsAsciiHex(const char Character) noexcept -> bool
    {
        return (Character >= '0' && Character <= '9') ||
               (Character >= 'a' && Character <= 'f') ||
               (Character >= 'A' && Character <= 'F');
    }

    [[nodiscard]] inline auto ToAsciiLower(const char Character) noexcept -> char
    {
        if (Character >= 'A' && Character <= 'Z')
        {
            return static_cast<char>(Character + ('a' - 'A'));
        }
        return Character;
    }

    [[nodiscard]] inline auto EqualAsciiInsensitive(const std::string_view Left,
                                                    const std::string_view Right) noexcept -> bool
    {
        if (Left.size() != Right.size())
        {
            return false;
        }
        for (std::size_t Index = 0; Index < Left.size(); ++Index)
        {
            if (ToAsciiLower(Left[Index]) != ToAsciiLower(Right[Index]))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto IsValidServerNamePattern(std::string_view Name,
                                                       const bool AllowWildcard) noexcept -> bool
    {
        if (Name.size() > 253U)
        {
            return false;
        }
        if (Name.starts_with("*."))
        {
            if (!AllowWildcard)
            {
                return false;
            }
            Name.remove_prefix(2U);
        }
        else if (Name.find('*') != std::string_view::npos)
        {
            return false;
        }
        if (Name.empty())
        {
            return false;
        }

        std::size_t LabelStart = 0;
        while (LabelStart < Name.size())
        {
            const auto Dot = Name.find('.', LabelStart);
            const auto LabelEnd = Dot == std::string_view::npos ? Name.size() : Dot;
            const auto Label = Name.substr(LabelStart, LabelEnd - LabelStart);
            if (Label.empty() || Label.size() > 63U || Label.front() == '-' || Label.back() == '-')
            {
                return false;
            }
            for (const auto Character : Label)
            {
                if (!IsAsciiAlphaNumeric(Character) && Character != '-')
                {
                    return false;
                }
            }
            if (Dot == std::string_view::npos)
            {
                return true;
            }
            LabelStart = Dot + 1U;
        }
        return false;
    }

    enum class ServerNameRequirement : std::uint8_t
    {
        Optional,
        Required,
    };

    struct ServerNameValidationPolicy final
    {
        ServerNameRequirement Requirement{ServerNameRequirement::Optional};
        bool AllowWildcard{false};
        bool AllowNoSni{false};
    };

    [[nodiscard]] inline auto ValidateServerNames(const std::vector<std::string> &Names,
                                                   const std::string &Path,
                                                   const ServerNameValidationPolicy Policy) -> Result
    {
        if (Names.empty())
        {
            if (Policy.Requirement == ServerNameRequirement::Required)
            {
                return Failure(ConfigurationErrorCode::MissingField,
                               Path,
                               "at least one ServerName is required");
            }
            return {};
        }
        for (std::size_t Index = 0; Index < Names.size(); ++Index)
        {
            if (Policy.AllowNoSni && Names[Index].empty())
            {
                continue;
            }
            if (!IsValidServerNamePattern(Names[Index], Policy.AllowWildcard))
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + "[" + std::to_string(Index) + "]",
                               "ServerName must be a valid DNS name or supported wildcard");
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateAlpnList(const std::vector<std::string> &Alpn,
                                               const std::string &Path) -> Result
    {
        for (std::size_t Index = 0; Index < Alpn.size(); ++Index)
        {
            const auto &Protocol = Alpn[Index];
            if (Protocol.empty() || Protocol.size() > 255U)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + "[" + std::to_string(Index) + "]",
                               "ALPN identifiers must contain between 1 and 255 bytes");
            }
            for (const auto Byte : Protocol)
            {
                const auto Value = static_cast<unsigned char>(Byte);
                if (Value < 0x21U || Value > 0x7eU)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + "[" + std::to_string(Index) + "]",
                                   "ALPN identifiers must use visible ASCII characters");
                }
            }
        }
        return {};
    }

    [[nodiscard]] inline auto IsValidPort(const std::string_view Port) noexcept -> bool
    {
        if (Port.empty())
        {
            return false;
        }
        std::uint32_t Value = 0;
        const auto [End, Error] = std::from_chars(Port.data(), Port.data() + Port.size(), Value, 10);
        return Error == std::errc{} && End == Port.data() + Port.size() &&
               Value > 0U && Value <= std::numeric_limits<std::uint16_t>::max();
    }

    [[nodiscard]] inline auto IsValidHost(const std::string_view Host) -> bool
    {
        if (Host.empty())
        {
            return false;
        }
        boost::system::error_code Error;
        (void)boost::asio::ip::make_address(std::string(Host), Error);
        return !Error || IsValidServerNamePattern(Host, false);
    }

    [[nodiscard]] inline auto IsValidHostPort(const std::string_view Value,
                                              const bool RequirePort) -> bool
    {
        if (Value.empty())
        {
            return false;
        }
        if (Value.front() == '[')
        {
            const auto Close = Value.find(']');
            if (Close == std::string_view::npos)
            {
                return false;
            }
            boost::system::error_code Error;
            const auto Address = boost::asio::ip::make_address(
                std::string(Value.substr(1U, Close - 1U)), Error);
            if (Error || !Address.is_v6())
            {
                return false;
            }
            const auto Suffix = Value.substr(Close + 1U);
            if (Suffix.empty())
            {
                return !RequirePort;
            }
            return Suffix.front() == ':' && IsValidPort(Suffix.substr(1U));
        }

        const auto Separator = Value.find(':');
        if (Separator == std::string_view::npos)
        {
            return !RequirePort && IsValidHost(Value);
        }
        if (Value.find(':', Separator + 1U) != std::string_view::npos ||
            !IsValidHost(Value.substr(0, Separator)))
        {
            return false;
        }
        return IsValidPort(Value.substr(Separator + 1U));
    }

    [[nodiscard]] inline auto ValidateHostPort(const std::string &Value,
                                               const std::string &Path,
                                               const std::string_view Field) -> Result
    {
        if (!IsValidHostPort(Value, true))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Path,
                           std::string(Field) + " must be a valid host:port target");
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateOptionalHost(const std::string &Value,
                                                   const std::string &Path) -> Result
    {
        if (!Value.empty() && !IsValidHostPort(Value, false))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Path,
                           "Host must be a valid host name with an optional port");
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateHttpPath(const std::string &Value,
                                               const std::string &Path) -> Result
    {
        if (Value.empty() || Value.front() != '/')
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Path,
                           "Path must be an absolute HTTP path beginning with /");
        }
        for (std::size_t Index = 0; Index < Value.size(); ++Index)
        {
            const auto Byte = static_cast<unsigned char>(Value[Index]);
            if (Byte <= 0x20U || Byte == 0x7fU || Value[Index] == '\\' || Value[Index] == '#')
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "Path contains an invalid HTTP path character");
            }
            if (Value[Index] == '%')
            {
                if (Index + 2U >= Value.size() || !IsAsciiHex(Value[Index + 1U]) ||
                    !IsAsciiHex(Value[Index + 2U]))
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path,
                                   "Path contains an invalid percent escape");
                }
                Index += 2U;
            }
        }
        return {};
    }

    [[nodiscard]] inline auto IsValidToken(const std::string_view Value,
                                            const std::size_t MaxLength) noexcept -> bool
    {
        if (Value.empty() || Value.size() > MaxLength)
        {
            return false;
        }
        for (const auto Character : Value)
        {
            if (!IsAsciiAlphaNumeric(Character) && Character != '.' && Character != '_' &&
                Character != '-')
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto ValidateShortIds(const std::vector<std::string> &ShortIds,
                                               const std::string &Path) -> Result
    {
        if (ShortIds.empty())
        {
            return Failure(ConfigurationErrorCode::MissingField,
                           Path,
                           "at least one ShortId is required");
        }
        for (std::size_t Index = 0; Index < ShortIds.size(); ++Index)
        {
            const auto &ShortId = ShortIds[Index];
            if (ShortId.size() > 16U || ShortId.size() % 2U != 0U ||
                !std::all_of(ShortId.begin(), ShortId.end(), IsAsciiHex))
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + "[" + std::to_string(Index) + "]",
                               "ShortId must be an even-length hex string of at most 16 characters");
            }
        }
        return {};
    }

    struct RestlsRuleCursor final
    {
        explicit RestlsRuleCursor(const std::string_view RuleValue) : Rule(RuleValue)
        {
        }

        [[nodiscard]] auto ReadUnsigned(const std::uint32_t Maximum) noexcept
            -> std::optional<std::uint32_t>
        {
            const auto Start = Position;
            while (Position < Rule.size() && Rule[Position] >= '0' && Rule[Position] <= '9')
            {
                ++Position;
            }
            if (Start == Position)
            {
                return std::nullopt;
            }
            std::uint32_t Number = 0;
            const auto [End, Error] = std::from_chars(
                Rule.data() + Start, Rule.data() + Position, Number, 10);
            if (Error != std::errc{} || End != Rule.data() + Position || Number > Maximum)
            {
                return std::nullopt;
            }
            return Number;
        }

        [[nodiscard]] auto Consume(const char Expected) noexcept -> bool
        {
            if (Position >= Rule.size() || Rule[Position] != Expected)
            {
                return false;
            }
            ++Position;
            return true;
        }

        [[nodiscard]] auto AtEnd() const noexcept -> bool
        {
            return Position == Rule.size();
        }

        std::string_view Rule;
        std::size_t Position{0};
    };

    [[nodiscard]] inline auto IsValidRestlsScript(const std::string_view Script) noexcept -> bool
    {
        constexpr auto MaxTarget = static_cast<std::uint32_t>(
            std::numeric_limits<std::int16_t>::max());
        std::size_t RuleStart = 0;
        for (;;)
        {
            const auto Comma = Script.find(',', RuleStart);
            const auto Rule = Script.substr(
                RuleStart, Comma == std::string_view::npos ? Script.size() - RuleStart
                                                           : Comma - RuleStart);
            RestlsRuleCursor Cursor(Rule);
            const auto Base = Cursor.ReadUnsigned(MaxTarget);
            if (!Base)
            {
                return false;
            }
            if (Cursor.Consume('?') || Cursor.Consume('~'))
            {
                const auto Range = Cursor.ReadUnsigned(MaxTarget);
                if (!Range || *Base + *Range > MaxTarget)
                {
                    return false;
                }
            }
            if (Cursor.Consume('<'))
            {
                if (!Cursor.ReadUnsigned(std::numeric_limits<std::uint8_t>::max()))
                {
                    return false;
                }
            }
            if (!Cursor.AtEnd())
            {
                return false;
            }
            if (Comma == std::string_view::npos)
            {
                return true;
            }
            RuleStart = Comma + 1U;
            if (RuleStart == Script.size())
            {
                return false;
            }
        }
    }

    [[nodiscard]] inline auto ValidateRecognitionRoute(
        const Prism::Contract::RecognitionRouteConfiguration &Recognition,
        const std::string &Path) -> Result
    {
        if (!Recognition.Pattern.empty() &&
            !IsValidServerNamePattern(Recognition.Pattern, true))
        {
            return Failure(ConfigurationErrorCode::InvalidValue,
                           Path + ".Pattern",
                           "Pattern must be a valid DNS name or supported wildcard");
        }
        return {};
    }

} // namespace Prism::Application::Configuration::Validation
