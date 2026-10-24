/** @file Parser.cpp @brief HTTP/1.1 请求解析与 CONNECT 序列化实现。 */
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Protocols/Http1/Detail/ParserSupport.hpp>

#include <cctype>
#include <charconv>
#include <cstddef>
#include <system_error>
#include <string>
#include <utility>

#include <boost/asio/ip/address_v6.hpp>

namespace Prism::Http11
{

    namespace detail
    {
        auto ToLower(const char Character) noexcept -> char
        {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(Character)));
        }

        auto Iequals(const std::string_view Left, const std::string_view Right) noexcept -> bool
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

        auto IstartsWith(const std::string_view Value, const std::string_view Prefix) noexcept -> bool
        {
            return Value.size() >= Prefix.size() && Iequals(Value.substr(0, Prefix.size()), Prefix);
        }

        auto IsTokenChar(const char Character) noexcept -> bool
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

        auto ParsePort(const std::string_view Text) noexcept -> std::optional<std::uint16_t>
        {
            if (Text.empty())
            {
                return std::nullopt;
            }
            unsigned Value = 0;
            const auto [Next, Error] = std::from_chars(Text.data(), Text.data() + Text.size(), Value);
            if (Error != std::errc{} || Next != Text.data() + Text.size() || Value == 0 || Value > 65535U)
            {
                return std::nullopt;
            }
            return static_cast<std::uint16_t>(Value);
        }

        auto ParseAuthority(
            const std::string_view Authority,
            const std::uint16_t DefaultPort,
            const bool RequirePort) -> std::optional<ProxyTarget>
        {
            if (Authority.empty() || Authority.find('@') != std::string_view::npos)
            {
                return std::nullopt;
            }

            std::string_view Host;
            std::string_view PortText;
            if (Authority.front() == '[')
            {
                const auto Close = Authority.find(']');
                if (Close == std::string_view::npos || Close == 1U)
                {
                    return std::nullopt;
                }
                Host = Authority.substr(1, Close - 1);
                boost::system::error_code AddressError;
                (void)boost::asio::ip::make_address_v6(Host, AddressError);
                if (AddressError)
                {
                    return std::nullopt;
                }
                const auto Suffix = Authority.substr(Close + 1);
                if (!Suffix.empty())
                {
                    if (Suffix.front() != ':' || Suffix.size() == 1U)
                    {
                        return std::nullopt;
                    }
                    PortText = Suffix.substr(1);
                }
                else if (RequirePort)
                {
                    return std::nullopt;
                }
            }
            else
            {
                const auto FirstColon = Authority.find(':');
                const auto LastColon = Authority.rfind(':');
                if (FirstColon != std::string_view::npos && FirstColon != LastColon)
                {
                    return std::nullopt;
                }
                if (FirstColon == std::string_view::npos)
                {
                    if (RequirePort)
                    {
                        return std::nullopt;
                    }
                    Host = Authority;
                }
                else
                {
                    Host = Authority.substr(0, FirstColon);
                    PortText = Authority.substr(FirstColon + 1);
                    if (PortText.empty())
                    {
                        return std::nullopt;
                    }
                }
            }

            if (Host.empty())
            {
                return std::nullopt;
            }
            const auto Port = PortText.empty() ? std::optional<std::uint16_t>{DefaultPort}
                                               : ParsePort(PortText);
            if (!Port)
            {
                return std::nullopt;
            }
            return ProxyTarget{std::string(Host), *Port, RequestForm::Origin};
        }

        auto AbsoluteAuthority(const std::string_view Target) noexcept
            -> std::optional<std::pair<std::string_view, std::uint16_t>>
        {
            std::uint16_t DefaultPort = 0;
            std::size_t PrefixSize = 0;
            if (IstartsWith(Target, "http://"))
            {
                DefaultPort = 80;
                PrefixSize = 7;
            }
            else if (IstartsWith(Target, "https://"))
            {
                DefaultPort = 443;
                PrefixSize = 8;
            }
            else
            {
                return std::nullopt;
            }

            const auto Remainder = Target.substr(PrefixSize);
            const auto End = Remainder.find_first_of("/?#");
            const auto Authority = End == std::string_view::npos ? Remainder : Remainder.substr(0, End);
            if (Authority.empty())
            {
                return std::nullopt;
            }
            return std::pair{Authority, DefaultPort};
        }

        auto OriginForm(const std::string_view Target) -> std::optional<std::string>
        {
            const auto Absolute = AbsoluteAuthority(Target);
            if (!Absolute)
            {
                return std::string(Target);
            }
            const auto SchemeEnd = Target.find("://");
            const auto AuthorityEnd = Target.find_first_of("/?#", SchemeEnd + 3U);
            const auto PathOffset = AuthorityEnd == std::string_view::npos
                                        ? Target.size()
                                        : AuthorityEnd;
            const auto Remainder = Target.substr(PathOffset);
            if (Remainder.empty())
            {
                return std::string{"/"};
            }
            if (Remainder.front() == '#')
            {
                return std::nullopt;
            }
            if (Remainder.front() == '?')
            {
                return "/" + std::string(Remainder);
            }
            return std::string(Remainder);
        }
    } // namespace detail

    auto ParseRequest(std::string_view Raw, HttpRequest& Request) -> Fault::Code
    {
        Request = {};
        if (Raw.size() > MaxHdrSize)
        {
            return Fault::Code::ParseError;
        }
        const auto LineEnd = Raw.find("\r\n");
        if (LineEnd == std::string_view::npos)
        {
            return Fault::Code::ParseError;
        }
        const auto FirstSpace = Raw.find(' ');
        if (FirstSpace == std::string_view::npos || FirstSpace >= LineEnd)
        {
            return Fault::Code::ParseError;
        }
        const auto SecondSpace = Raw.find(' ', FirstSpace + 1U);
        if (SecondSpace == std::string_view::npos || SecondSpace >= LineEnd)
        {
            return Fault::Code::ParseError;
        }
        Request.Method = Raw.substr(0, FirstSpace);
        Request.Target = Raw.substr(FirstSpace + 1U, SecondSpace - FirstSpace - 1U);
        Request.version = Raw.substr(SecondSpace + 1U, LineEnd - SecondSpace - 1U);
        if (Request.Method.empty() || Request.Target.empty() || Request.version != "HTTP/1.1")
        {
            return Fault::Code::ParseError;
        }
        for (const auto Character : Request.Method)
        {
            if (!detail::IsTokenChar(Character))
            {
                return Fault::Code::ParseError;
            }
        }
        Request.LineEnd = LineEnd + 2U;

        const auto HeadersEnd = Raw.find("\r\n\r\n", LineEnd);
        if (HeadersEnd == std::string_view::npos)
        {
            return Fault::Code::ParseError;
        }
        Request.HdrEnd = HeadersEnd + 4U;
        const auto HeaderBlockStart = LineEnd + 2U;
        const auto HeaderBlockSize = HeadersEnd >= HeaderBlockStart
            ? HeadersEnd - HeaderBlockStart : std::size_t{0};
        auto ParsedHeaders = HeaderFields::Parse(
            Raw.substr(HeaderBlockStart, HeaderBlockSize));
        if (!ParsedHeaders)
        {
            return Fault::Code::ParseError;
        }
        Request.host = ParsedHeaders->Host;
        Request.authorization = ParsedHeaders->ProxyAuthorization;
        Request.Headers = std::move(*ParsedHeaders);
        return Fault::Code::Success;
    }

    auto ResolveTarget(const HttpRequest& Request) -> std::optional<ProxyTarget>
    {
        if (Request.Target.find('#') != std::string_view::npos ||
            detail::IstartsWith(Request.Target, "https://"))
        {
            return std::nullopt;
        }
        if (Request.Method == "CONNECT")
        {
            auto Result = detail::ParseAuthority(Request.Target, 443, true);
            if (!Result)
            {
                return std::nullopt;
            }
            Result->Form = RequestForm::Connect;
            return Result;
        }
        if (const auto Absolute = detail::AbsoluteAuthority(Request.Target))
        {
            auto Result = detail::ParseAuthority(Absolute->first, Absolute->second, false);
            if (!Result)
            {
                return std::nullopt;
            }
            Result->Form = RequestForm::Absolute;
            return Result;
        }
        if (Request.Target.starts_with('/') || Request.Target == "*")
        {
            auto Result = detail::ParseAuthority(Request.host, 80, false);
            if (!Result)
            {
                return std::nullopt;
            }
            Result->Form = RequestForm::Origin;
            return Result;
        }
        return std::nullopt;
    }

    auto MakeConnectRequest(std::string_view Host, const std::uint16_t Port,
        const std::string_view Authorization) -> std::string
    {
        std::string Request;
        Request.reserve(64U + Authorization.size());
        Request.append("CONNECT ").append(Host).push_back(':');
        Request.append(std::to_string(Port));
        Request.append(" HTTP/1.1\r\nHost: ").append(Host).push_back(':');
        Request.append(std::to_string(Port)).append("\r\n");
        if (!Authorization.empty())
        {
            Request.append("Proxy-Authorization: ").append(Authorization).append("\r\n");
        }
        Request.append("\r\n");
        return Request;
    }

    auto ParseStatusCode(std::string_view Raw) -> int
    {
        if (!Raw.starts_with("HTTP/"))
        {
            return 0;
        }
        const auto LineEnd = Raw.find("\r\n");
        if (LineEnd == std::string_view::npos)
        {
            return 0;
        }
        const auto FirstSpace = Raw.find(' ');
        if (FirstSpace == std::string_view::npos || FirstSpace + 1U >= LineEnd)
        {
            return 0;
        }
        int Code = 0;
        for (std::size_t Index = FirstSpace + 1U;
             Index < LineEnd && std::isdigit(static_cast<unsigned char>(Raw[Index])); ++Index)
        {
            Code = Code * 10 + (Raw[Index] - '0');
        }
        return Code;
    }

} // namespace Prism::Http11
