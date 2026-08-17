/**
 * @file parser.hpp
 * @brief HTTP/1.1 CONNECT 请求解析与构造（T3-5 / D4）
 * @details 自包含 HTTP/1.1 子集：
 *          - parse_request：请求行 + 头字段解析（Host / Proxy-Authorization）
 *          - make_connect_request：客户端构造 CONNECT 请求
 *          - parse_status_code：响应行状态码提取（客户端验证）
 * @note 参照主项目 src/prism/protocol/http/codec/parser.cpp，测试库自包含实现
 */

#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <common/core/fault/code.hpp>

namespace preview::http11
{

    /**
     * @struct http_request
     * @brief 解析后的 HTTP 请求（视图，不拷贝正文）
     */
    struct http_request
    {
        std::string_view method;        ///< 方法（CONNECT）
        std::string_view target;        ///< 目标（host:port）
        std::string_view version;       ///< 版本（HTTP/1.1）
        std::string_view host;          ///< Host 头
        std::string_view authorization; ///< Proxy-Authorization 头
        std::size_t line_end{0};        ///< 请求行结束偏移（\r\n 之后）
        std::size_t hdr_end{0};         ///< 头块结束偏移（\r\n\r\n 之后）
    };

    namespace detail
    {
        /// @brief 字符转小写
        [[nodiscard]] inline auto to_lower(const char c) noexcept -> char
        {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        /// @brief 大小写不敏感比较
        [[nodiscard]] inline auto iequals(std::string_view l, std::string_view r) noexcept
            -> bool
        {
            if (l.size() != r.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < l.size(); ++i)
            {
                if (to_lower(l[i]) != to_lower(r[i]))
                {
                    return false;
                }
            }
            return true;
        }

        /// @brief 去除首尾空白
        [[nodiscard]] inline auto trim(std::string_view v) noexcept -> std::string_view
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
    [[nodiscard]] inline auto parse_request(std::string_view raw, http_request &out) -> fault::code
    {
        const auto line_end = raw.find("\r\n");
        if (line_end == std::string_view::npos)
        {
            return fault::code::parse_error;
        }

        const auto first_space = raw.find(' ');
        if (first_space == std::string_view::npos || first_space >= line_end)
        {
            return fault::code::parse_error;
        }
        const auto second_space = raw.find(' ', first_space + 1);
        if (second_space == std::string_view::npos || second_space >= line_end)
        {
            return fault::code::parse_error;
        }

        out.method = raw.substr(0, first_space);
        out.target = raw.substr(first_space + 1, second_space - first_space - 1);
        out.version = raw.substr(second_space + 1, line_end - second_space - 1);
        out.line_end = line_end + 2;

        const auto headers_end = raw.find("\r\n\r\n", line_end);
        if (headers_end == std::string_view::npos)
        {
            return fault::code::parse_error;
        }
        out.hdr_end = headers_end + 4;

        // 遍历头字段，提取 Host 与 Proxy-Authorization
        std::string_view block = raw.substr(line_end + 2, headers_end - line_end - 2);
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
            const auto name = detail::trim(line.substr(0, colon));
            const auto value = detail::trim(line.substr(colon + 1));
            if (detail::iequals(name, "host"))
            {
                out.host = value;
            }
            else if (detail::iequals(name, "proxy-authorization"))
            {
                out.authorization = value;
            }
        }
        return fault::code::success;
    }

    /**
     * @brief 构造 CONNECT 请求
     * @param host 目标主机
     * @param port 目标端口
     * @param authorization Basic 凭据（可选，为空则不含该头）
     * @return 完整请求字节串
     */
    [[nodiscard]] inline auto make_connect_request(std::string_view host, const std::uint16_t port,
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
    [[nodiscard]] inline auto parse_status_code(std::string_view raw) -> int
    {
        if (!raw.starts_with("HTTP/"))
        {
            return 0;
        }
        const auto line_end = raw.find("\r\n");
        if (line_end == std::string_view::npos)
        {
            return 0;
        }
        const auto first_space = raw.find(' ');
        if (first_space == std::string_view::npos || first_space + 1 >= line_end)
        {
            return 0;
        }
        int code = 0;
        for (std::size_t i = first_space + 1; i < line_end && std::isdigit(
                                                           static_cast<unsigned char>(raw[i]));
             ++i)
        {
            code = code * 10 + (raw[i] - '0');
        }
        return code;
    }

} // namespace preview::http11
