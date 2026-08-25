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

#include <common/Core/Fault/Code.hpp>

namespace Preview::Http11
{

    /**
     * @struct HttpRequest
     * @brief 解析后的 HTTP 请求（视图，不拷贝正文）
     */
    struct HttpRequest
    {
        std::string_view Method;        ///< 方法（CONNECT）
        std::string_view Target;        ///< 目标（host:port）
        std::string_view version;       ///< 版本（HTTP/1.1）
        std::string_view host;          ///< Host 头
        std::string_view authorization; ///< Proxy-Authorization 头
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
        [[nodiscard]] inline auto Iequals(std::string_view l, std::string_view r) noexcept
            -> bool
        {
            if (l.size() != r.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < l.size(); ++i)
            {
                if (ToLower(l[i]) != ToLower(r[i]))
                {
                    return false;
                }
            }
            return true;
        }

        /// @brief 去除首尾空白
        [[nodiscard]] inline auto Trim(std::string_view v) noexcept -> std::string_view
        {
            auto s = v;
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
            {
                s.remove_prefix(1);
            }
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
            {
                s.remove_suffix(1);
            }
            return s;
        }
    } // namespace detail

    /**
     * @brief 解析 HTTP 请求
     * @param raw 原始数据（含请求行 + 头块）
     * @param out 解析结果
     * @return 成功或 parse_error
     */
    [[nodiscard]] inline auto ParseRequest(std::string_view raw, HttpRequest &out) -> Fault::Code
    {
        const auto LineEnd = raw.find("\r\n");
        if (LineEnd == std::string_view::npos)
        {
            return Fault::Code::parse_error;
        }

        const auto FirstSpace = raw.find(' ');
        if (FirstSpace == std::string_view::npos || FirstSpace >= LineEnd)
        {
            return Fault::Code::parse_error;
        }
        const auto SecondSpace = raw.find(' ', FirstSpace + 1);
        if (SecondSpace == std::string_view::npos || SecondSpace >= LineEnd)
        {
            return Fault::Code::parse_error;
        }

        out.Method = raw.substr(0, FirstSpace);
        out.Target = raw.substr(FirstSpace + 1, SecondSpace - FirstSpace - 1);
        out.version = raw.substr(SecondSpace + 1, LineEnd - SecondSpace - 1);
        out.LineEnd = LineEnd + 2;

        const auto HeadersEnd = raw.find("\r\n\r\n", LineEnd);
        if (HeadersEnd == std::string_view::npos)
        {
            return Fault::Code::parse_error;
        }
        out.HdrEnd = HeadersEnd + 4;

        // 遍历头字段，提取 Host 与 Proxy-Authorization
        std::string_view block = raw.substr(LineEnd + 2, HeadersEnd - LineEnd - 2);
        while (!block.empty())
        {
            const auto next = block.find("\r\n");
            std::string_view line;
            if (next == std::string_view::npos)
            {
                line = block;
                block = {};
            }
            else
            {
                line = block.substr(0, next);
                block = block.substr(next + 2);
            }

            const auto colon = line.find(':');
            if (colon == std::string_view::npos)
            {
                continue;
            }
            const auto Name = detail::Trim(line.substr(0, colon));
            const auto value = detail::Trim(line.substr(colon + 1));
            if (detail::Iequals(Name, "host"))
            {
                out.host = value;
            }
            else if (detail::Iequals(Name, "proxy-authorization"))
            {
                out.authorization = value;
            }
        }
        return Fault::Code::success;
    }

    /**
     * @brief 构造 CONNECT 请求
     * @param host 目标主机
     * @param port 目标端口
     * @param authorization Basic 凭据（可选，为空则不含该头）
     * @return 完整请求字节串
     */
    [[nodiscard]] inline auto MakeConnectRequest(std::string_view host, const std::uint16_t port,
                                                   const std::string_view authorization = {})
        -> std::string
    {
        std::string req;
        req.reserve(64 + authorization.size());
        req.append("CONNECT ").append(host).push_back(':');
        req.append(std::to_string(port));
        req.append(" HTTP/1.1\r\nHost: ").append(host).push_back(':');
        req.append(std::to_string(port)).append("\r\n");
        if (!authorization.empty())
        {
            req.append("Proxy-Authorization: ").append(authorization).append("\r\n");
        }
        req.append("\r\n");
        return req;
    }

    /**
     * @brief 提取响应行状态码
     * @param raw 响应头数据
     * @return 状态码（解析失败返回 0）
     */
    [[nodiscard]] inline auto ParseStatusCode(std::string_view raw) -> int
    {
        if (!raw.starts_with("HTTP/"))
        {
            return 0;
        }
        const auto LineEnd = raw.find("\r\n");
        if (LineEnd == std::string_view::npos)
        {
            return 0;
        }
        const auto FirstSpace = raw.find(' ');
        if (FirstSpace == std::string_view::npos || FirstSpace + 1 >= LineEnd)
        {
            return 0;
        }
        int Code = 0;
        for (std::size_t i = FirstSpace + 1; i < LineEnd && std::isdigit(
                                                           static_cast<unsigned char>(raw[i]));
             ++i)
        {
            Code = Code * 10 + (raw[i] - '0');
        }
        return Code;
    }

} // namespace Preview::Http11
