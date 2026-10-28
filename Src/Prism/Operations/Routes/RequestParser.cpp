/** @file RequestParser.cpp @brief Operations HTTP/1.1 请求头增量解析实现。 */
#include <Prism/Operations/Routes/RequestParser.hpp>
#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/Http/Limits.hpp>

#include <cctype>
#include <cstddef>
#include <string_view>

namespace Prism::Operations::RequestParserDetail
{
    auto ToLower(const char Value) noexcept -> char
    {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(Value)));
    }

    auto EqualsInsensitive(const std::string_view Left, const std::string_view Right) noexcept -> bool
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

    auto IsTokenCharacter(const char Value) noexcept -> bool
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

    auto IsFieldValueCharacter(const char Value) noexcept -> bool
    {
        const auto Byte = static_cast<unsigned char>(Value);
        return Byte == '\t' || (Byte >= 0x20U && Byte != 0x7fU);
    }

    auto Trim(const std::string_view Value) noexcept -> std::string_view
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

    auto ReadRequestLine(std::string_view RequestLine, HttpRequest &Request) -> ParseStatus
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

    auto HeaderBlockParser::ReadLine(const std::string_view Line) -> ParseStatus
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

    auto HeaderBlockParser::Finish() const noexcept -> ParseStatus
    {
        if (!HostSeen || TransferEncodingSeen)
        {
            return ParseStatus::Malformed;
        }
        return ParseStatus::Complete;
    }

    auto ReadHeaderBlock(std::string_view HeaderBlock, HttpRequest &Request) -> ParseStatus
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

    auto ParseRequestHeaders(const std::string_view Raw, HttpRequest &Request) -> ParseStatus
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

    auto ParseRequest(const std::string_view Raw, HttpRequest &Request) -> ParseStatus
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

        // Pre-check authorization BEFORE reserving body budget to prevent DoS
        // Critical fix: Reject unauthorized requests with non-zero Content-Length early
        if (Request.ContentLength != 0U)
        {
            const auto QueryStart = Request.Target.find('?');
            const auto Path = Request.Target.substr(0, QueryStart);

            // Only allow POST /Operations/Reload/application/json for requests with body
            if (Request.Method != "POST" || Path != "/Operations/Reload" ||
                Request.ContentType != "application/json")
            {
                // Early rejection prevents resource exhaustion from large Content-Length
                return ParseStatus::Malformed;
            }
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
        Request.Body = Raw.substr(Request.HeaderEnd, Request.ContentLength);
        return ParseStatus::Complete;
    }
}
