/**
 * @file ForwardRequest.hpp
 * @brief HTTP/1.1 普通正向代理请求序列化接口
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>

namespace Prism::Http11
{
    struct HttpRequest;

    /**
     * @enum ForwardBodyMode
     * @brief 首个 HTTP/1.1 请求的消息体边界
     */
    enum class ForwardBodyMode : std::uint8_t
    {
        None,
        ContentLength,
        Chunked,
    };

    /**
     * @struct ForwardRequestOptions
     * @brief 构造首请求边界传输所需的拥有数据
     * @details Header 与 Preread 均转移所有权；Parsed 中的 string_view 不得跨越
     *          ServerConn 生命周期，调用方必须先将消息定界值复制到本结构。
     *          AwaitUpgrade 为 true 时，首请求完成后只在上游完整响应 101 后进入隧道。
     */
    struct ForwardRequestOptions final
    {
        SharedTransmission Inner;
        std::string Header;
        std::vector<std::byte> Preread;
        ForwardBodyMode BodyMode{ForwardBodyMode::None};
        std::uint64_t ContentLength{0};
        bool AwaitUpgrade{false};
    };

    [[nodiscard]] auto BuildForwardRequest(std::string_view Raw,
                                           const HttpRequest &Request) -> std::string;

    /**
     * @brief 构造有界首请求转发传输
     * @param Options 首请求头、预读数据与 framing 所有权
     * @return 新传输；读到首请求边界返回 clean EOF，错误通过传输错误码返回
     * @note 写方向始终委托内层，以便 clean EOF 后继续传递下游响应；Close/Cancel
     *       负责内层最终关闭/取消，Executor 与内层一致。
     */
    [[nodiscard]] auto MakeForwardRequestTransport(ForwardRequestOptions Options)
        -> SharedTransmission;
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

    inline auto BuildForwardRequest(std::string_view Raw, const HttpRequest &Request) -> std::string
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

#include <Prism/Protocols/Http1/ForwardRequestTransport.hpp>
