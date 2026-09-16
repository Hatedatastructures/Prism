/**
 * @file Parser.hpp
 * @brief HTTP/1.1 入站代理请求解析与构造
 * @details 自包含 HTTP/1.1 子集：
 *          - ParseRequest：请求行 + 头字段解析（Host / Proxy-Authorization）
 *          - ResolveTarget：解析 CONNECT authority、absolute-form 和 origin-form
 *          - BuildForwardRequest：将代理请求行改写为源站 origin-form
 *          - MakeConnectRequest：客户端构造 CONNECT 请求
 *          - ParseStatusCode：响应行状态码提取（客户端验证）
 * @note 参照主项目 src/prism/Protocol/http/Codec/Parser.cpp，测试库自包含实现
 */

#pragma once

#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <boost/asio/ip/address_v6.hpp>

#include <Preview/Foundation/Fault/Code.hpp>

namespace Preview::Http11
{

    /// 最大 HTTP 头部大小（防慢速输入和解析阶段内存增长）
    inline constexpr std::size_t MaxHdrSize = 65536;

    /**
     * @struct HttpRequest
     * @brief 解析后的 HTTP 请求（视图，不拷贝正文）
     */
    struct HttpRequest
    {
        std::string_view Method;        ///< 请求方法
        std::string_view Target;        ///< authority、absolute-form 或 origin-form 目标
        std::string_view version;       ///< 版本（HTTP/1.1；保留兼容字段名）
        std::string_view host;          ///< Host 头（保留兼容字段名）
        std::string_view authorization; ///< Proxy-Authorization 头（保留兼容字段名）
        std::size_t LineEnd{0};        ///< 请求行结束偏移（\r\n 之后）
        std::size_t HdrEnd{0};         ///< 头块结束偏移（\r\n\r\n 之后）
    };

    /// HTTP 代理请求目标的请求形态
    enum class RequestForm : std::uint8_t
    {
        Connect,
        Absolute,
        Origin,
    };

    /**
     * @struct ProxyTarget
     * @brief HTTP 入站代理解析后的拨号目标
     */
    struct ProxyTarget
    {
        std::string Host;
        std::uint16_t Port{0};
        RequestForm Form{RequestForm::Origin};
    };

    namespace detail
    {
        /// @brief 字符转小写
        [[nodiscard]] inline auto ToLower(const char c) noexcept -> char
        {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        /// @brief 大小写不敏感比较
        [[nodiscard]] inline auto Iequals(std::string_view Left, std::string_view Right) noexcept
            -> bool
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

        /// @brief 大小写不敏感前缀比较
        [[nodiscard]] inline auto IstartsWith(std::string_view Value, std::string_view Prefix) noexcept
            -> bool
        {
            return Value.size() >= Prefix.size() &&
                   Iequals(Value.substr(0, Prefix.size()), Prefix);
        }

        /// RFC 7230 tchar
        [[nodiscard]] inline auto IsTokenChar(const char Character) noexcept -> bool
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

        /// RFC 7230 field-value 中允许的可见字符和 HTAB
        [[nodiscard]] inline auto IsFieldValueChar(const char Character) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Character);
            return Byte == '\t' || Byte >= 0x20;
        }

        /// @brief 去除首尾空白
        [[nodiscard]] inline auto Trim(std::string_view Value) noexcept -> std::string_view
        {
            auto Trimmed = Value;
            while (!Trimmed.empty() && (Trimmed.front() == ' ' || Trimmed.front() == '\t'))
            {
                Trimmed.remove_prefix(1);
            }
            while (!Trimmed.empty() && (Trimmed.back() == ' ' || Trimmed.back() == '\t'))
            {
                Trimmed.remove_suffix(1);
            }
            return Trimmed;
        }

        [[nodiscard]] inline auto ParsePort(std::string_view Text) noexcept
            -> std::optional<std::uint16_t>
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

        [[nodiscard]] inline auto ParseAuthority(std::string_view Authority,
                                                 std::uint16_t DefaultPort,
                                                 bool RequirePort) -> std::optional<ProxyTarget>
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

        [[nodiscard]] inline auto AbsoluteAuthority(std::string_view Target) noexcept
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

        [[nodiscard]] inline auto OriginForm(std::string_view Target) -> std::optional<std::string>
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

    /**
     * @brief 解析 HTTP 请求
     * @param Raw 原始数据（含请求行 + 头块）
     * @param Request 解析结果
     * @return 成功或 parse_error
     */
    [[nodiscard]] inline auto ParseRequest(
        std::string_view Raw,
        HttpRequest &Request) -> Fault::Code
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
        const auto SecondSpace = Raw.find(' ', FirstSpace + 1);
        if (SecondSpace == std::string_view::npos || SecondSpace >= LineEnd)
        {
            return Fault::Code::ParseError;
        }

        Request.Method = Raw.substr(0, FirstSpace);
        Request.Target = Raw.substr(FirstSpace + 1, SecondSpace - FirstSpace - 1);
        Request.version = Raw.substr(SecondSpace + 1, LineEnd - SecondSpace - 1);
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
        Request.LineEnd = LineEnd + 2;

        const auto HeadersEnd = Raw.find("\r\n\r\n", LineEnd);
        if (HeadersEnd == std::string_view::npos)
        {
            return Fault::Code::ParseError;
        }
        Request.HdrEnd = HeadersEnd + 4;

        // 遍历头字段，提取 Host 与 Proxy-Authorization
        std::string_view HeaderBlock = Raw.substr(LineEnd + 2, HeadersEnd - LineEnd - 2);
        bool HostSeen = false;
        bool AuthorizationSeen = false;
        while (!HeaderBlock.empty())
        {
            const auto Next = HeaderBlock.find("\r\n");
            std::string_view Line;
            if (Next == std::string_view::npos)
            {
                Line = HeaderBlock;
                HeaderBlock = {};
            }
            else
            {
                Line = HeaderBlock.substr(0, Next);
                HeaderBlock = HeaderBlock.substr(Next + 2);
            }

            if (Line.empty() || Line.front() == ' ' || Line.front() == '\t')
            {
                return Fault::Code::ParseError;
            }
            const auto Colon = Line.find(':');
            if (Colon == std::string_view::npos || Colon == 0)
            {
                return Fault::Code::ParseError;
            }
            const auto Name = Line.substr(0, Colon);
            for (const auto Character : Name)
            {
                if (!detail::IsTokenChar(Character))
                {
                    return Fault::Code::ParseError;
                }
            }
            const auto RawValue = Line.substr(Colon + 1);
            for (const auto Character : RawValue)
            {
                if (!detail::IsFieldValueChar(Character) || Character == '\x7F')
                {
                    return Fault::Code::ParseError;
                }
            }
            const auto Value = detail::Trim(RawValue);
            if (detail::Iequals(Name, "host"))
            {
                if (HostSeen)
                {
                    return Fault::Code::ParseError;
                }
                HostSeen = true;
                Request.host = Value;
            }
            else if (detail::Iequals(Name, "proxy-authorization"))
            {
                if (AuthorizationSeen)
                {
                    return Fault::Code::ParseError;
                }
                AuthorizationSeen = true;
                Request.authorization = Value;
            }
        }
        return Fault::Code::Success;
    }

    /**
     * @brief 解析 HTTP 入站代理请求的拨号目标
     * @param Request 已解析的请求
     * @return 目标和请求形态；格式非法时为空
     */
    [[nodiscard]] inline auto ResolveTarget(const HttpRequest &Request)
        -> std::optional<ProxyTarget>
    {
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

    /**
     * @brief 构建转发到源站的 HTTP 请求
     * @param Raw 已读取的请求头和共包正文
     * @param Request Raw 对应的解析结果
     * @return origin-form 请求；CONNECT 或格式非法时为空
     * @details 只改写请求行，头字段和已经读取的正文按原始字节保留。
     */
    [[nodiscard]] inline auto BuildForwardRequest(std::string_view Raw,
                                                   const HttpRequest &Request) -> std::string
    {
        const auto Resolved = ResolveTarget(Request);
        if (!Resolved || Resolved->Form == RequestForm::Connect || Request.LineEnd > Raw.size())
        {
            return {};
        }
        const auto Target = detail::OriginForm(Request.Target);
        if (!Target || Target->empty())
        {
            return {};
        }
        std::string Result;
        Result.reserve(Request.Method.size() + Target->size() + Request.version.size() +
                       2U + Raw.size() - Request.LineEnd);
        Result.append(Request.Method);
        Result.push_back(' ');
        Result.append(*Target);
        Result.push_back(' ');
        Result.append(Request.version);
        Result.append("\r\n");
        Result.append(Raw.substr(Request.LineEnd));
        return Result;
    }

    /**
     * @brief 构造 CONNECT 请求
     * @param Host 目标主机
     * @param Port 目标端口
     * @param Authorization Basic 凭据（可选，为空则不含该头）
     * @return 完整请求字节串
     */
    [[nodiscard]] inline auto MakeConnectRequest(
        std::string_view Host,
        const std::uint16_t Port,
        const std::string_view Authorization = {})
        -> std::string
    {
        std::string Request;
        Request.reserve(64 + Authorization.size());
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

    /**
     * @brief 提取响应行状态码
     * @param Raw 响应头数据
     * @return 状态码（解析失败返回 0）
     */
    [[nodiscard]] inline auto ParseStatusCode(std::string_view Raw) -> int
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
        if (FirstSpace == std::string_view::npos || FirstSpace + 1 >= LineEnd)
        {
            return 0;
        }
        int Code = 0;
        for (std::size_t Index = FirstSpace + 1;
             Index < LineEnd && std::isdigit(static_cast<unsigned char>(Raw[Index]));
             ++Index)
        {
            Code = Code * 10 + (Raw[Index] - '0');
        }
        return Code;
    }

} // namespace Preview::Http11
