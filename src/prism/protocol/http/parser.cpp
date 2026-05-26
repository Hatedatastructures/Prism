#include <prism/protocol/http/parser.hpp>
#include <prism/account/directory.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/sha224.hpp>

#include <cctype>
#include <cstdint>
#include <cstring>

namespace psm::protocol::http
{

    namespace
    {
        // 字符转小写
        [[nodiscard]] auto to_lower(const std::uint8_t c) noexcept
            -> char
        {
            return static_cast<char>(std::tolower(c));
        }

        // 大小写不敏感字符串比较
        [[nodiscard]] auto iequals(const std::string_view left, const std::string_view right) noexcept
            -> bool
        {
            if (left.size() != right.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < left.size(); ++i)
            {
                if (to_lower(static_cast<std::uint8_t>(left[i])) != to_lower(static_cast<std::uint8_t>(right[i])))
                {
                    return false;
                }
            }
            return true;
        }

        // 去除首尾空白字符
        [[nodiscard]] auto trim(const std::string_view value) noexcept
            -> std::string_view
        {
            auto s = value;
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

        // 大小写不敏感前缀匹配
        [[nodiscard]] auto iequals_prefix(const std::string_view str, const std::string_view prefix) noexcept
            -> bool
        {
            if (str.size() <= prefix.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < prefix.size(); ++i)
            {
                if (to_lower(static_cast<std::uint8_t>(str[i])) != to_lower(static_cast<std::uint8_t>(prefix[i])))
                {
                    return false;
                }
            }
            return true;
        }

        // 407 Proxy Authentication Required 响应
        constexpr std::string_view resp407 = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                             "Proxy-Authenticate: Basic\r\n"
                                             "Content-Length: 0\r\n"
                                             "\r\n";

        // 403 Forbidden 响应
        constexpr std::string_view resp403 = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";

        // Basic 认证方案前缀
        constexpr std::string_view basic_prefix = "Basic ";
    } // namespace

    auto authenticate_proxy(const std::string_view authorization, account::directory &directory)
        -> auth_result
    {
        // 验证 Basic 认证方案前缀（大小写不敏感）
        if (!iequals_prefix(authorization, basic_prefix))
        {
            auth_result result;
            result.authenticated = false;
            result.error_response = resp407;
            return result;
        }

        // Base64 解码凭据
        const auto decoded = crypto::base64_decode(authorization.substr(basic_prefix.size()));
        const auto colon_pos = decoded.find(':');

        if (colon_pos != std::string::npos && colon_pos < decoded.size() - 1)
        {
            // 提取密码并计算 SHA224 哈希
            const auto password = std::string_view(decoded).substr(colon_pos + 1);
            const auto credential = crypto::sha224(password);
            auto acquired = account::try_acquire(directory, credential);

            if (acquired)
            {
                auth_result ok;
                ok.authenticated = true;
                ok.lease = std::move(acquired);
                return ok;
            }

            auth_result denied;
            denied.authenticated = false;
            denied.error_response = resp403;
            return denied;
        }

        auth_result bad;
        bad.authenticated = false;
        bad.error_response = resp403;
        return bad;
    }

    auto build_fwd(const proxy_request &req, std::pmr::memory_resource *mr)
        -> memory::string
    {
        const auto relative = rel_path(req.target);

        memory::string new_line(mr);
        new_line.reserve(req.method.size() + 1 + relative.size() + 1 + req.version.size() + 2);
        new_line.append(req.method);
        new_line.push_back(' ');
        new_line.append(relative);
        new_line.push_back(' ');
        new_line.append(req.version);
        new_line.append("\r\n");

        return new_line;
    }

    auto parse_req(const std::string_view raw_data, proxy_request &out)
        -> fault::code
    {
        // 定位请求行末尾
        const auto line_end = raw_data.find("\r\n");
        if (line_end == std::string_view::npos)
        {
            return fault::code::parse_error;
        }

        // 解析请求行: METHOD TARGET HTTP/version
        const auto first_space = raw_data.find(' ');
        if (first_space == std::string_view::npos || first_space >= line_end)
        {
            return fault::code::parse_error;
        }

        const auto second_space = raw_data.find(' ', first_space + 1);
        if (second_space == std::string_view::npos || second_space >= line_end)
        {
            return fault::code::parse_error;
        }

        out.method = raw_data.substr(0, first_space);
        out.target = raw_data.substr(first_space + 1, second_space - first_space - 1);
        out.version = raw_data.substr(second_space + 1, line_end - second_space - 1);
        out.line_end = line_end + 2;

        // 定位头部结束标记 \r\n\r\n
        const auto headers_end = raw_data.find("\r\n\r\n", line_end);
        if (headers_end == std::string_view::npos)
        {
            return fault::code::parse_error;
        }
        out.hdr_end = headers_end + 4;

        // 遍历头字段，提取 Host 和 Proxy-Authorization
        std::string_view block = raw_data.substr(line_end + 2, headers_end - line_end - 2);
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

            if (line.empty())
            {
                continue;
            }

            const auto colon = line.find(':');
            if (colon == std::string_view::npos)
            {
                continue;
            }

            const auto name = trim(line.substr(0, colon));
            const auto value = trim(line.substr(colon + 1));

            if (iequals(name, "host"))
            {
                out.host = value;
            }
            else if (iequals(name, "proxy-authorization"))
            {
                out.authorization = value;
            }
        }

        return fault::code::success;
    }

    auto rel_path(const std::string_view target)
        -> std::string_view
    {
        // 跳过 scheme
        std::string_view working = target;
        if (working.starts_with("http://"))
        {
            working.remove_prefix(7);
        }
        else if (working.starts_with("https://"))
        {
            working.remove_prefix(8);
        }
        else
        {
            return target; // 非绝对 URI，原样返回
        }

        // 跳过 authority，定位 path
        const auto slash_pos = working.find('/');
        if (slash_pos == std::string_view::npos)
        {
            return {"/", 1};
        }

        // 计算在原始 target 中的偏移
        const auto offset = target.size() - working.size() + slash_pos;
        return target.substr(offset);
    }

} // namespace psm::protocol::http
