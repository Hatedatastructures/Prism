/**
 * @file HeaderFields.cpp
 * @brief HTTP/1.1 请求头字段解析实现。
 */
#include <Prism/Foundation/Utility/Http/HeaderFields.hpp>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>
#include <vector>

namespace Prism::Http11::HeaderFields
{
    namespace
    {
        struct TransferCodingState final
        {
            bool ChunkedSeen{false};
            bool FinalChunked{false};
        };

        [[nodiscard]] auto IsTokenChar(const char Character) noexcept -> bool
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

        [[nodiscard]] auto IsFieldValueChar(const char Character) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Character);
            return Byte == '\t' || (Byte >= 0x20U && Byte != 0x7fU);
        }

        [[nodiscard]] auto Trim(std::string_view Value) noexcept -> std::string_view
        {
            while (!Value.empty() && (Value.front() == ' ' || Value.front() == '\t'))
            {
                Value.remove_prefix(1);
            }
            while (!Value.empty() && (Value.back() == ' ' || Value.back() == '\t'))
            {
                Value.remove_suffix(1);
            }
            return Value;
        }

        [[nodiscard]] auto Iequals(std::string_view Left, std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                auto A = static_cast<unsigned char>(Left[Index]);
                auto B = static_cast<unsigned char>(Right[Index]);
                if (A >= 'A' && A <= 'Z')
                {
                    A = static_cast<unsigned char>(A + ('a' - 'A'));
                }
                if (B >= 'A' && B <= 'Z')
                {
                    B = static_cast<unsigned char>(B + ('a' - 'A'));
                }
                if (A != B)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto IsToken(std::string_view Value) noexcept -> bool
        {
            if (Value.empty())
            {
                return false;
            }
            for (const auto Character : Value)
            {
                if (!IsTokenChar(Character))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto ParseConnectionOptions(std::string_view Value, Parsed &Headers) -> bool
        {
            Value = Trim(Value);
            if (Value.empty())
            {
                return false;
            }
            while (true)
            {
                const auto Comma = Value.find(',');
                const auto Token = Trim(Value.substr(0, Comma));
                if (!IsToken(Token))
                {
                    return false;
                }
                Headers.ConnectionOptions.push_back(Token);
                if (Comma == std::string_view::npos)
                {
                    return true;
                }
                Value.remove_prefix(Comma + 1U);
            }
        }

        [[nodiscard]] auto AppendTransferCodings(std::string_view Value,
                                                 TransferCodingState &State) -> bool
        {
            Value = Trim(Value);
            if (Value.empty())
            {
                return false;
            }
            std::size_t Offset = 0;
            const auto SkipOws = [&]()
            {
                while (Offset < Value.size() && (Value[Offset] == ' ' || Value[Offset] == '\t'))
                {
                    ++Offset;
                }
            };
            const auto ReadToken = [&]() -> std::string_view
            {
                const auto Start = Offset;
                while (Offset < Value.size() && IsTokenChar(Value[Offset]))
                {
                    ++Offset;
                }
                return Value.substr(Start, Offset - Start);
            };

            while (Offset < Value.size())
            {
                const auto Coding = ReadToken();
                if (Coding.empty() || State.ChunkedSeen)
                {
                    return false;
                }
                SkipOws();
                bool HasParameters = false;
                while (Offset < Value.size() && Value[Offset] == ';')
                {
                    HasParameters = true;
                    ++Offset;
                    SkipOws();
                    if (ReadToken().empty())
                    {
                        return false;
                    }
                    SkipOws();
                    if (Offset >= Value.size() || Value[Offset] != '=')
                    {
                        return false;
                    }
                    ++Offset;
                    SkipOws();
                    if (Offset < Value.size() && Value[Offset] == '"')
                    {
                        ++Offset;
                        bool Closed = false;
                        while (Offset < Value.size())
                        {
                            auto Character = Value[Offset++];
                            if (Character == '"')
                            {
                                Closed = true;
                                break;
                            }
                            if (Character == '\\')
                            {
                                if (Offset >= Value.size())
                                {
                                    return false;
                                }
                                Character = Value[Offset++];
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
                    else if (ReadToken().empty())
                    {
                        return false;
                    }
                    SkipOws();
                }
                const auto IsChunked = Iequals(Coding, "chunked");
                if (IsChunked && HasParameters)
                {
                    return false;
                }
                State.ChunkedSeen = IsChunked;
                State.FinalChunked = IsChunked;
                if (Offset == Value.size())
                {
                    return true;
                }
                if (Value[Offset++] != ',')
                {
                    return false;
                }
                SkipOws();
                if (Offset == Value.size())
                {
                    return false;
                }
            }
            return false;
        }

        [[nodiscard]] auto IsValidUpgradeValue(std::string_view Value) noexcept -> bool
        {
            Value = Trim(Value);
            if (Value.empty())
            {
                return false;
            }
            while (true)
            {
                const auto Comma = Value.find(',');
                const auto Protocol = Trim(Value.substr(0, Comma));
                const auto Slash = Protocol.find('/');
                if (Slash == std::string_view::npos)
                {
                    if (!IsToken(Protocol))
                    {
                        return false;
                    }
                }
                else if (Protocol.find('/', Slash + 1U) != std::string_view::npos ||
                         !IsToken(Protocol.substr(0, Slash)) || !IsToken(Protocol.substr(Slash + 1U)))
                {
                    return false;
                }
                if (Comma == std::string_view::npos)
                {
                    return true;
                }
                Value.remove_prefix(Comma + 1U);
            }
        }

        [[nodiscard]] auto ParseContentLength(std::string_view Value) noexcept
            -> std::optional<std::uint64_t>
        {
            if (Value.empty())
            {
                return std::nullopt;
            }
            std::uint64_t Length = 0;
            const auto [Next, Error] = std::from_chars(Value.data(), Value.data() + Value.size(), Length);
            if (Error != std::errc{} || Next != Value.data() + Value.size())
            {
                return std::nullopt;
            }
            return Length;
        }

        [[nodiscard]] auto ParseField(std::string_view Line, Field &Output) -> bool
        {
            if (Line.empty() || Line.front() == ' ' || Line.front() == '\t')
            {
                return false;
            }
            const auto Colon = Line.find(':');
            if (Colon == std::string_view::npos || Colon == 0)
            {
                return false;
            }
            Output.Name = Line.substr(0, Colon);
            Output.RawValue = Line.substr(Colon + 1U);
            for (const auto Character : Output.Name)
            {
                if (!IsTokenChar(Character))
                {
                    return false;
                }
            }
            for (const auto Character : Output.RawValue)
            {
                if (!IsFieldValueChar(Character))
                {
                    return false;
                }
            }
            return true;
        }
    } // namespace

    auto Parsed::ConnectionContains(std::string_view Name) const noexcept -> bool
    {
        for (const auto Option : ConnectionOptions)
        {
            if (Iequals(Option, Name))
            {
                return true;
            }
        }
        return false;
    }

    auto Parsed::ContentTypeIs(std::string_view Expected) const noexcept -> bool
    {
        if (ContentType.empty())
        {
            return false;
        }
        const auto Separator = ContentType.find(';');
        const auto MediaType = Separator == std::string_view::npos
            ? ContentType
            : ContentType.substr(0, Separator);
        return Iequals(Trim(MediaType), Expected);
    }

    auto Parse(std::string_view HeaderBlock) -> std::optional<Parsed>
    {
        if (HeaderBlock.size() > MaxHeaderBlockBytes)
        {
            return std::nullopt;
        }

        Parsed Result;
        TransferCodingState TransferCodings;
        bool HostSeen = false;
        bool AuthorizationSeen = false;
        while (!HeaderBlock.empty())
        {
            const auto Next = HeaderBlock.find("\r\n");
            const auto Line = Next == std::string_view::npos ? HeaderBlock : HeaderBlock.substr(0, Next);
            HeaderBlock = Next == std::string_view::npos ? std::string_view{} : HeaderBlock.substr(Next + 2U);
            Field Current;
            if (!ParseField(Line, Current))
            {
                return std::nullopt;
            }
            Result.Fields.push_back(Current);
            const auto Value = Trim(Current.RawValue);
            if (Iequals(Current.Name, "host"))
            {
                if (HostSeen)
                {
                    return std::nullopt;
                }
                HostSeen = true;
                Result.Host = Value;
            }
            else if (Iequals(Current.Name, "proxy-authorization"))
            {
                if (AuthorizationSeen)
                {
                    return std::nullopt;
                }
                AuthorizationSeen = true;
                Result.ProxyAuthorization = Value;
            }
            else if (Iequals(Current.Name, "connection"))
            {
                if (!ParseConnectionOptions(Current.RawValue, Result))
                {
                    return std::nullopt;
                }
            }
            else if (Iequals(Current.Name, "content-length"))
            {
                const auto Length = ParseContentLength(Value);
                if (Result.HasContentLength || !Length)
                {
                    return std::nullopt;
                }
                Result.HasContentLength = true;
                Result.ContentLength = *Length;
            }
            else if (Iequals(Current.Name, "transfer-encoding"))
            {
                if (!AppendTransferCodings(Value, TransferCodings))
                {
                    return std::nullopt;
                }
                Result.HasTransferEncoding = true;
            }
            else if (Iequals(Current.Name, "content-type"))
            {
                if (!Result.ContentType.empty())
                {
                    return std::nullopt;
                }
                Result.ContentType = Value;
            }
            else if (Iequals(Current.Name, "upgrade"))
            {
                if (!IsValidUpgradeValue(Value))
                {
                    return std::nullopt;
                }
                Result.HasUpgrade = true;
            }
        }

        Result.FinalTransferCodingChunked = TransferCodings.FinalChunked;
        if ((Result.HasContentLength && Result.HasTransferEncoding) ||
            (Result.HasContentLength && Result.ConnectionContains("content-length")) ||
            (Result.HasTransferEncoding && Result.ConnectionContains("transfer-encoding")) ||
            Result.ConnectionContains("host") ||
            (Result.HasTransferEncoding && !Result.FinalTransferCodingChunked))
        {
            return std::nullopt;
        }
        return Result;
    }

} // namespace Prism::Http11::HeaderFields
