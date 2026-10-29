/**
 * @file Request.cpp
 * @brief HTTP/1.1 正向代理请求序列化实现
 */

#include <Prism/Protocols/Http1/Forward/Request.hpp>

#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Protocols/Http1/Detail/ParserSupport.hpp>

#include <cstddef>
#include <string_view>

namespace Prism::Http11
{
    namespace
    {
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

        auto AppendField(std::string &Output, std::string_view Name, std::string_view RawValue) -> void
        {
            Output.append(Name);
            Output.push_back(':');
            Output.append(RawValue);
            Output.append("\r\n");
        }

        auto AppendAuthorityHost(std::string &Output, std::string_view Authority) -> void
        {
            Output.append("Host: ");
            Output.append(Authority);
            Output.append("\r\n");
        }

        [[nodiscard]] auto IsAlwaysHopByHop(std::string_view Name) noexcept -> bool
        {
            return Iequals(Name, "proxy-authorization") || Iequals(Name, "proxy-connection") ||
                   Iequals(Name, "keep-alive") || Iequals(Name, "te");
        }
    } // namespace

    auto BuildForwardRequest(std::string_view Raw, const HttpRequest &Request) -> std::string
    {
        const auto Resolved = ResolveTarget(Request);
        if (!Resolved || Resolved->Form == RequestForm::Connect || Request.LineEnd > Raw.size() ||
            Request.HdrEnd > Raw.size() || Request.HdrEnd < 4U || Request.HdrEnd - 4U < Request.LineEnd)
        {
            return {};
        }
        const auto HeaderEnd = Request.HdrEnd - 4U;
        if (Raw.substr(HeaderEnd, 4U) != "\r\n\r\n")
        {
            return {};
        }
        if ((Request.Headers.HasContentLength &&
             (Request.Headers.HasTransferEncoding || Request.Headers.ConnectionContains("content-length"))) ||
            (Request.Headers.HasTransferEncoding &&
             (!Request.Headers.FinalTransferCodingChunked ||
              Request.Headers.ConnectionContains("transfer-encoding"))))
        {
            return {};
        }

        const auto Target = detail::OriginForm(Request.Target);
        if (!Target || Target->empty())
        {
            return {};
        }
        std::string_view Authority;
        const auto IsAbsolute = Resolved->Form == RequestForm::Absolute;
        if (IsAbsolute)
        {
            const auto Absolute = detail::AbsoluteAuthority(Request.Target);
            if (!Absolute)
            {
                return {};
            }
            Authority = Absolute->first;
        }
        else if (Request.Headers.Host.empty())
        {
            return {};
        }

        const auto UpgradeRequested = Request.Headers.HasUpgrade &&
                                      Request.Headers.ConnectionContains("upgrade");
        std::string Output;
        Output.reserve(Raw.size());
        Output.append(Request.Method);
        Output.push_back(' ');
        Output.append(*Target);
        Output.push_back(' ');
        Output.append(Request.version);
        Output.append("\r\n");

        bool HostWritten = false;
        if (IsAbsolute && Request.Headers.Host.empty())
        {
            AppendAuthorityHost(Output, Authority);
            HostWritten = true;
        }
        bool UpgradeConnectionWritten = false;
        for (const auto &Field : Request.Headers.Fields)
        {
            if (Iequals(Field.Name, "connection"))
            {
                if (UpgradeRequested && !UpgradeConnectionWritten)
                {
                    Output.append("Connection: Upgrade\r\n");
                    UpgradeConnectionWritten = true;
                }
                continue;
            }
            if (Iequals(Field.Name, "host"))
            {
                if (!HostWritten)
                {
                    if (IsAbsolute || Request.Headers.ConnectionContains("host"))
                    {
                        AppendAuthorityHost(Output, IsAbsolute ? Authority : Request.Headers.Host);
                    }
                    else
                    {
                        AppendField(Output, Field.Name, Field.RawValue);
                    }
                    HostWritten = true;
                }
                continue;
            }
            if (IsAlwaysHopByHop(Field.Name))
            {
                continue;
            }
            if (Iequals(Field.Name, "upgrade"))
            {
                if (UpgradeRequested)
                {
                    AppendField(Output, Field.Name, Field.RawValue);
                }
                continue;
            }
            if (Request.Headers.ConnectionContains(Field.Name))
            {
                continue;
            }
            AppendField(Output, Field.Name, Field.RawValue);
        }
        Output.append("\r\n");
        Output.append(Raw.substr(Request.HdrEnd));
        return Output;
    }
} // namespace Prism::Http11
