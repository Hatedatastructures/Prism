/**
 * @file Parser.hpp
 * @brief HTTP/1.1 CONNECT 请求解析与构造（T3-5 / D4）
 * @details 自包含 HTTP/1.1 子集：
 *          - ParseRequest：请求行 + 头字段解析（Host / Proxy-Authorization）
 *          - MakeConnectRequest：客户端构造 CONNECT 请求
 *          - ParseStatusCode：响应行状态码提取（客户端验证）
 * @note 参照主项目 src/prism/Protocol/http/Codec/Parser.cpp，测试库自包含实现
 */

#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <preview/Foundation/Fault/Code.hpp>

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
        std::string_view Method;        ///< 方法（CONNECT）
        std::string_view Target;        ///< 目标（host:port）
        std::string_view version;       ///< 版本（HTTP/1.1；保留兼容字段名）
        std::string_view host;          ///< Host 头（保留兼容字段名）
        std::string_view authorization; ///< Proxy-Authorization 头（保留兼容字段名）
        std::size_t LineEnd{0};        ///< 请求行结束偏移（\r\n 之后）
        std::size_t HdrEnd{0};         ///< 头块结束偏移（\r\n\r\n 之后）
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
        if (Request.Method != "CONNECT" || Request.Target.empty() || Request.version != "HTTP/1.1")
        {
            return Fault::Code::ParseError;
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
