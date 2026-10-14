/**
 * @file RequestParser.hpp
 * @brief Operations HTTP/1.1 请求头解析 owner。
 * @details 解析结果只借用调用方缓冲区；不拥有 socket、路由或业务状态。
 */

#pragma once

#include <Preview/Operations/HttpServer.hpp>

#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace Preview::Operations::RequestParserDetail
{

    enum class ParseStatus : std::uint8_t
    {
        Complete,
        Incomplete,
        Malformed,
        Oversized,
    };

    [[nodiscard]] inline auto ToLower(const char Value) noexcept -> char
    {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(Value)));
    }

    [[nodiscard]] inline auto EqualsInsensitive(const std::string_view Left,
                                                const std::string_view Right) noexcept -> bool
    {
        if (Left.size() != Right.size())
        {
            return false;
        }
        for (std::size_t Index = 0; Index < Left.size(); ++Index)
        {
            if (ToLower(Left[Index]) != ToLower(Right[Index]))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto IsTokenCharacter(const char Value) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Value);
        if ((Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z') ||
            (Byte >= '0' && Byte <= '9'))
        {
            return true;
        }
        constexpr std::string_view Punctuation{"!#$%&'*+-.^_`|~"};
        return Punctuation.find(Value) != std::string_view::npos;
    }

    [[nodiscard]] inline auto IsFieldValueCharacter(const char Value) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Value);
        return Byte == '\t' || (Byte >= 0x20U && Byte != 0x7fU);
    }

    [[nodiscard]] inline auto Trim(const std::string_view Value) noexcept -> std::string_view
    {
        auto Result = Value;
        while (!Result.empty() && (Result.front() == ' ' || Result.front() == '\t'))
        {
            Result.remove_prefix(1);
        }
        while (!Result.empty() && (Result.back() == ' ' || Result.back() == '\t'))
        {
            Result.remove_suffix(1);
        }
        return Result;
    }

    template <typename Value>
    [[nodiscard]] inline auto ParseUnsigned(const std::string_view Text, Value &Result) -> bool
    {
        if (Text.empty())
        {
            return false;
        }
        Value Parsed{};
        const auto *First = Text.data();
        const auto *Last = First + Text.size();
        const auto [End, Error] = std::from_chars(First, Last, Parsed, 10);
        if (Error != std::errc{} || End != Last)
        {
            return false;
        }
        Result = Parsed;
        return true;
    }

    /** @brief 解析唯一 HTTP/1.1 请求行；输出借用调用者的原始请求缓冲。 */
    [[nodiscard]] inline auto ReadRequestLine(std::string_view RequestLine,
                                             HttpRequest &Request) -> ParseStatus
    {
        const auto FirstSpace = RequestLine.find(' ');
        auto SecondSpace = std::string_view::npos;
        if (FirstSpace != std::string_view::npos)
        {
            SecondSpace = RequestLine.find(' ', FirstSpace + 1U);
        }
        if (FirstSpace == std::string_view::npos || SecondSpace == std::string_view::npos ||
            FirstSpace == 0U || SecondSpace <= FirstSpace + 1U || SecondSpace >= RequestLine.size() ||
            RequestLine.find(' ', SecondSpace + 1U) != std::string_view::npos)
        {
            return ParseStatus::Malformed;
        }
        Request.Method = RequestLine.substr(0, FirstSpace);
        Request.Target = RequestLine.substr(FirstSpace + 1U, SecondSpace - FirstSpace - 1U);
        const auto Version = RequestLine.substr(SecondSpace + 1U);
        if ((Request.Method != "GET" && Request.Method != "POST") || Request.Target.empty() ||
            Version != "HTTP/1.1")
        {
            return ParseStatus::Malformed;
        }
        for (const auto Character : Request.Target)
        {
            if (static_cast<unsigned char>(Character) < 0x21U || Character == 0x7f)
            {
                return ParseStatus::Malformed;
            }
        }

        return ParseStatus::Complete;
    }

    /** @brief 持有单个请求头块的字段唯一性与输出借用视图。 */
    struct HeaderBlockParser final
    {
        HttpRequest &Request;
        bool HostSeen{false};
        bool OriginSeen{false};
        bool AuthorizationSeen{false};
        bool ContentLengthSeen{false};
        bool ContentTypeSeen{false};
        bool TransferEncodingSeen{false};
        bool CorrelationSeen{false};
        std::size_t HeaderCount{0};

        [[nodiscard]] auto ReadLine(const std::string_view Line) -> ParseStatus
        {
            if (Line.empty() || Line.size() > MaxRequestLineBytes || ++HeaderCount > MaxHeaderCount)
            {
                if (Line.size() > MaxRequestLineBytes)
                {
                    return ParseStatus::Oversized;
                }
                return ParseStatus::Malformed;
            }
            const auto Colon = Line.find(':');
            if (Colon == std::string_view::npos || Colon == 0U)
            {
                return ParseStatus::Malformed;
            }
            const auto Name = Line.substr(0, Colon);
            for (const auto Character : Name)
            {
                if (!RequestParserDetail::IsTokenCharacter(Character))
                {
                    return ParseStatus::Malformed;
                }
            }
            const auto RawValue = Line.substr(Colon + 1U);
            for (const auto Character : RawValue)
            {
                if (!RequestParserDetail::IsFieldValueCharacter(Character))
                {
                    return ParseStatus::Malformed;
                }
            }
            const auto Value = RequestParserDetail::Trim(RawValue);
            if (RequestParserDetail::EqualsInsensitive(Name, "host"))
            {
                if (HostSeen || Value.empty())
                {
                    return ParseStatus::Malformed;
                }
                HostSeen = true;
                Request.Host = Value;
            }
            else if (RequestParserDetail::EqualsInsensitive(Name, "origin"))
            {
                if (OriginSeen || Value.empty())
                {
                    return ParseStatus::Malformed;
                }
                OriginSeen = true;
                Request.Origin = Value;
            }
            else if (RequestParserDetail::EqualsInsensitive(Name, "authorization"))
            {
                if (AuthorizationSeen || Value.empty())
                {
                    return ParseStatus::Malformed;
                }
                AuthorizationSeen = true;
                Request.Authorization = Value;
            }
            else if (RequestParserDetail::EqualsInsensitive(Name, "content-length"))
            {
                if (ContentLengthSeen ||
                    !RequestParserDetail::ParseUnsigned(Value, Request.ContentLength))
                {
                    return ParseStatus::Malformed;
                }
                if (Request.ContentLength > MaxReloadBodyBytes)
                {
                    return ParseStatus::Oversized;
                }
                ContentLengthSeen = true;
                Request.ContentLengthSeen = true;
            }
            else if (RequestParserDetail::EqualsInsensitive(Name, "content-type"))
            {
                if (ContentTypeSeen || Value.empty())
                {
                    return ParseStatus::Malformed;
                }
                ContentTypeSeen = true;
                Request.ContentType = Value;
            }
            else if (RequestParserDetail::EqualsInsensitive(Name, "transfer-encoding"))
            {
                TransferEncodingSeen = true;
            }
            else if (RequestParserDetail::EqualsInsensitive(Name, "x-correlation-id") ||
                     RequestParserDetail::EqualsInsensitive(Name, "correlation-id"))
            {
                if (CorrelationSeen || Value.empty())
                {
                    return ParseStatus::Malformed;
                }
                CorrelationSeen = true;
                Request.Correlation = Value;
            }
            return ParseStatus::Complete;
        }

        [[nodiscard]] auto Finish() const noexcept -> ParseStatus
        {
            if (!HostSeen || TransferEncodingSeen)
            {
                return ParseStatus::Malformed;
            }
            return ParseStatus::Complete;
        }
    };

    /** @brief 验证完整请求头块，拒绝重复关键头、非零 body 和 transfer encoding。 */
    [[nodiscard]] inline auto ReadHeaderBlock(std::string_view HeaderBlock,
                                             HttpRequest &Request) -> ParseStatus
    {
        HeaderBlockParser Parser{Request};
        std::size_t Offset = 0;
        while (Offset < HeaderBlock.size())
        {
            const auto End = HeaderBlock.find("\r\n", Offset);
            auto LineSize = HeaderBlock.size() - Offset;
            if (End != std::string_view::npos)
            {
                LineSize = End - Offset;
            }
            const auto Line = HeaderBlock.substr(Offset, LineSize);
            const auto Status = Parser.ReadLine(Line);
            if (Status != ParseStatus::Complete)
            {
                return Status;
            }
            if (End == std::string_view::npos)
            {
                break;
            }
            Offset = End + 2U;
        }
        return Parser.Finish();
    }

} // namespace Preview::Operations::RequestParserDetail

namespace Preview::Operations::RequestParserDetail
{

    [[nodiscard]] inline auto ParseRequestHeaders(const std::string_view Raw,
                                                  HttpRequest &Request) -> ParseStatus
    {
        Request = {};
        const auto HeadersEnd = Raw.find("\r\n\r\n");
        if (HeadersEnd == std::string_view::npos)
        {
            if (Raw.size() >= MaxRequestHeaderBytes)
            {
                return ParseStatus::Oversized;
            }
            return ParseStatus::Incomplete;
        }
        if (HeadersEnd + 4U > MaxRequestHeaderBytes)
        {
            return ParseStatus::Oversized;
        }
        const auto LineEnd = Raw.find("\r\n");
        if (LineEnd == std::string_view::npos)
        {
            return ParseStatus::Malformed;
        }
        if (LineEnd > MaxRequestLineBytes)
        {
            return ParseStatus::Oversized;
        }
        const auto LineStatus = ReadRequestLine(Raw.substr(0, LineEnd), Request);
        if (LineStatus != ParseStatus::Complete)
        {
            return LineStatus;
        }
        const auto HeaderBegin = LineEnd + 2U;
        const auto HeaderStatus = ReadHeaderBlock(
            Raw.substr(HeaderBegin, HeadersEnd - HeaderBegin), Request);
        if (HeaderStatus != ParseStatus::Complete)
        {
            return HeaderStatus;
        }
        Request.HeaderEnd = HeadersEnd + 4U;
        return ParseStatus::Complete;
    }

    [[nodiscard]] inline auto ParseRequest(const std::string_view Raw,
                                           HttpRequest &Request) -> ParseStatus
    {
        if (Raw.size() > MaxRequestBytes)
        {
            return ParseStatus::Oversized;
        }
        const auto HeaderStatus = ParseRequestHeaders(Raw, Request);
        if (HeaderStatus != ParseStatus::Complete)
        {
            return HeaderStatus;
        }
        const auto ExpectedSize = Request.HeaderEnd + Request.ContentLength;
        if (Raw.size() < ExpectedSize)
        {
            return ParseStatus::Incomplete;
        }
        if (Raw.size() != ExpectedSize)
        {
            return ParseStatus::Malformed;
        }
        if (Request.ContentLength != 0U)
        {
            const auto QueryStart = Request.Target.find('?');
            const auto Path = Request.Target.substr(0, QueryStart);
            if (Request.Method != "POST" || Path != "/Operations/Reload" ||
                Request.ContentType != "application/json")
            {
                return ParseStatus::Malformed;
            }
        }
        Request.Body = Raw.substr(Request.HeaderEnd, Request.ContentLength);
        return ParseStatus::Complete;
    }

} // namespace Preview::Operations::RequestParserDetail
