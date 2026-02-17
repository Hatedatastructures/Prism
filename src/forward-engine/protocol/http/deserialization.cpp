#include <forward-engine/protocol/http/deserialization.hpp>

namespace ngx::protocol::http
{
    namespace
    {
        [[nodiscard]] auto trim(std::string_view value) noexcept
            -> std::string_view
        {
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
            {
                value.remove_prefix(1);
            }

            while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
            {
                value.remove_suffix(1);
            }

            return value;
        }

        [[nodiscard]] auto iequals(const std::string_view left, const std::string_view right) noexcept
            -> bool
        {
            if (left.size() != right.size())
            {
                return false;
            }

            for (std::size_t index = 0; index < left.size(); ++index)
            {
                const unsigned char left_ch = static_cast<unsigned char>(left[index]);
                const unsigned char right_ch = static_cast<unsigned char>(right[index]);

                if (std::tolower(left_ch) != std::tolower(right_ch))
                {
                    return false;
                }
            }

            return true;
        }

        [[nodiscard]] auto parse_http_version(std::string_view version_part, unsigned int &version_value) noexcept
            -> bool
        {
            if (!version_part.starts_with("HTTP/"))
            {
                return false;
            }

            // 移除 "HTTP/" 前缀
            version_part.remove_prefix(5);

            if (version_part.size() < 3 || version_part[1] != '.')
            {
                return false;
            }

            // eg : 1.1 -> 11
            const char major_char = version_part[0];
            const char minor_char = version_part[2];

            if (major_char < '0' || major_char > '9' || minor_char < '0' || minor_char > '9')
            { // 过滤非法数字
                return false;
            }

            const unsigned int major = static_cast<unsigned int>(major_char - '0');
            const unsigned int minor = static_cast<unsigned int>(minor_char - '0');

            // 构建数值
            version_value = major * 10 + minor;
            return true;
        }

        [[nodiscard]] auto parse_status_code(const std::string_view value, unsigned int &status_code_value) noexcept
            -> bool
        {
            if (value.size() != 3)
            {
                return false;
            }

            unsigned int code = 0;
            for (char ch : value)
            {
                if (ch < '0' || ch > '9')
                {
                    return false;
                }
                code = code * 10 + static_cast<unsigned int>(ch - '0');
            }

            status_code_value = code;
            return true;
        }
    } // namespace

    auto deserialize(const std::string_view string_value, request &http_request, memory::resource_pointer mr)
        -> gist::code
    {
        request parsed_request(mr ? mr : memory::current_resource());

        const std::size_t request_line_end = string_value.find("\r\n");
        if (request_line_end == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        const std::string_view request_line = string_value.substr(0, request_line_end);

        const std::size_t first_space = request_line.find(' ');
        if (first_space == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        const std::size_t second_space = request_line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        const std::string_view method_part = request_line.substr(0, first_space);
        const std::string_view target_part = request_line.substr(first_space + 1, second_space - first_space - 1);
        const std::string_view version_part = request_line.substr(second_space + 1);

        unsigned int version_value = 0;
        if (!parse_http_version(version_part, version_value))
        {
            return gist::code::parse_error;
        }

        parsed_request.method(method_part);
        parsed_request.target(target_part);
        parsed_request.version(version_value);

        const std::size_t headers_start = request_line_end + 2;
        const std::size_t headers_end = string_value.find("\r\n\r\n", headers_start);
        if (headers_end == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        std::string_view headers_block = string_value.substr(headers_start, headers_end - headers_start);

        while (!headers_block.empty())
        {
            const std::size_t line_end = headers_block.find("\r\n");
            std::string_view line;
            if (line_end == std::string_view::npos)
            {
                line = headers_block; // 处理最后一行
                headers_block.remove_prefix(headers_block.size());
            }
            else
            {
                line = headers_block.substr(0, line_end);
                // 移除处理好地行和换行符
                headers_block.remove_prefix(line_end + 2);
            }

            if (line.empty())
            {
                continue;
            }

            // 分离头字段名和值
            const std::size_t colon_pos = line.find(':');
            if (colon_pos == std::string_view::npos)
            {
                return gist::code::parse_error;
            }

            // 去除头字段名和值的首尾空格
            const std::string_view name = trim(line.substr(0, colon_pos));
            const std::string_view value = trim(line.substr(colon_pos + 1));

            if (name.empty())
            {
                return gist::code::parse_error;
            }

            parsed_request.set(name, value);
        }

        const std::size_t body_start = headers_end + 4;
        if (body_start < string_value.size())
        {
            const std::string_view body_view = string_value.substr(body_start);
            if (!body_view.empty())
            {
                parsed_request.body(body_view);
            }
        }

        const std::string_view connection_value = parsed_request.at("Connection");
        if (!connection_value.empty())
        {
            if (iequals(connection_value, "keep-alive"))
            {
                parsed_request.keep_alive(true);
            }
            else if (iequals(connection_value, "close"))
            {
                parsed_request.keep_alive(false);
            }
        }
        else if (parsed_request.version() == 11)
        {
            parsed_request.keep_alive(true);
        }

        http_request = std::move(parsed_request);
        return gist::code::success;
    }

    auto deserialize(const std::string_view string_value, response &http_response)
        -> gist::code
    {
        http_response.clear();

        // 1. 分离状态行
        const std::size_t status_line_end = string_value.find("\r\n");
        if (status_line_end == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        const std::string_view status_line = string_value.substr(0, status_line_end);

        const std::size_t first_space = status_line.find(' ');
        if (first_space == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        const std::size_t second_space = status_line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        const std::string_view version_part = status_line.substr(0, first_space);
        const std::string_view status_code_part = status_line.substr(first_space + 1, second_space - first_space - 1);
        const std::string_view reason_part = status_line.substr(second_space + 1);

        // 2. 解析 HTTP 版本
        unsigned int version_value = 0;
        if (!parse_http_version(version_part, version_value))
        {
            return gist::code::parse_error;
        }

        // 3. 解析状态码
        unsigned int status_code_value = 0;
        if (!parse_status_code(status_code_part, status_code_value))
        {
            return gist::code::parse_error;
        }

        // 4. 设置对象属性
        http_response.version(version_value);
        http_response.status(status_code_value);
        http_response.reason(reason_part);

        // 5. 解析头字段块
        const std::size_t headers_start = status_line_end + 2;
        const std::size_t headers_end = string_value.find("\r\n\r\n", headers_start);
        if (headers_end == std::string_view::npos)
        {
            return gist::code::parse_error;
        }

        std::string_view headers_block = string_value.substr(headers_start, headers_end - headers_start);

        // 6. 解析头字段
        while (!headers_block.empty())
        {
            const std::size_t line_end = headers_block.find("\r\n");
            std::string_view line;
            if (line_end == std::string_view::npos)
            {
                line = headers_block;
                headers_block.remove_prefix(headers_block.size());
            }
            else
            {
                line = headers_block.substr(0, line_end);
                headers_block.remove_prefix(line_end + 2);
            }

            if (line.empty())
            {
                continue;
            }

            const std::size_t colon_pos = line.find(':');
            if (colon_pos == std::string_view::npos)
            {
                return gist::code::parse_error;
            }

            const std::string_view name = trim(line.substr(0, colon_pos));
            const std::string_view value = trim(line.substr(colon_pos + 1));

            if (name.empty())
            {
                return gist::code::parse_error;
            }

            http_response.set(name, value);
        }

        // 7. 解析实体主体
        const std::size_t body_start = headers_end + 4;
        if (body_start < string_value.size())
        {
            const std::string_view body_view = string_value.substr(body_start);
            if (!body_view.empty())
            {
                http_response.body(body_view);
            }
        }

        // 8. 兜底设置 Connection 头字段
        const std::string_view connection_value = http_response.at("Connection");
        if (!connection_value.empty())
        {
            if (iequals(connection_value, "keep-alive"))
            {
                http_response.keep_alive(true);
            }
            else if (iequals(connection_value, "close"))
            {
                http_response.keep_alive(false);
            }
        }
        else if (http_response.version() == 11)
        {
            http_response.keep_alive(true);
        }

        return gist::code::success;
    }

} // namespace ngx::protocol::http
