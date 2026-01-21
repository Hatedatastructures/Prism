#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/header.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <string>

namespace ngx::protocol::http
{
    namespace
    {
        /**
         * @brief 去除首尾空白字符
         * @details 该函数会去除字符串首尾的 `SP` 和 `HTAB`，用于解析头字段名。
         * 清理多余的空格。
         * @param value 输入字符串视图
         * @return std::string_view 去除首尾空白后的字符串视图
         */
        [[nodiscard]] std::string_view trim(std::string_view value) noexcept
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

        /**
         * @brief 忽略大小写比较字符串是否相等
         * @param left 左侧字符串视图
         * @param right 右侧字符串视图
         * @return bool 相等返回 `true`，否则返回 `false`
         */
        [[nodiscard]] bool iequals(std::string_view left, std::string_view right) noexcept
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

        /**
         * @brief 解析 `HTTP/1.x` 版本字符串
         * @details 输入形如 `HTTP/1.1` 的字符串视图，输出内部保存的版本值 `11`。
         * @param version_part 版本字符串视图
         * @param version_value 用于输出解析后的版本数值
         * @return bool 解析成功返回 `true`，否则返回 `false`
         */
        [[nodiscard]] bool parse_http_version(std::string_view version_part, unsigned int &version_value) noexcept
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
            {   // 过滤非法数字
                return false;
            }

            const unsigned int major = static_cast<unsigned int>(major_char - '0');
            const unsigned int minor = static_cast<unsigned int>(minor_char - '0');

            // 构建数值
            version_value = major * 10 + minor;
            return true;
        }

        /**
         * @brief 解析整型状态码
         * @details 要求状态码为三位十进制数字。
         * @param value 状态码字符串视图
         * @param status_code_value 输出的整型状态码
         * @return bool 解析成功返回 `true`，否则返回 `false`
         */
        [[nodiscard]] bool parse_status_code(std::string_view value, unsigned int &status_code_value) noexcept
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
                code = static_cast<unsigned int>(code * 10 + static_cast<unsigned int>(ch - '0'));
            }

            status_code_value = code;
            return true;
        }
    } // namespace

    bool deserialize(const std::string_view string_value, request &request_instance)
    {
        request_instance.clear();

        const std::size_t request_line_end = string_value.find("\r\n");
        if (request_line_end == std::string_view::npos)
        {
            return false;
        }

        const std::string_view request_line = string_value.substr(0, request_line_end);

        const std::size_t first_space = request_line.find(' ');
        if (first_space == std::string_view::npos)
        {
            return false;
        }

        const std::size_t second_space = request_line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos)
        {
            return false;
        }

        const std::string_view method_part = request_line.substr(0, first_space);
        const std::string_view target_part = request_line.substr(first_space + 1, second_space - first_space - 1);
        const std::string_view version_part = request_line.substr(second_space + 1);

        unsigned int version_value = 0;
        if (!parse_http_version(version_part, version_value))
        {
            return false;
        }

        request_instance.method(method_part);
        request_instance.target(target_part);
        request_instance.version(version_value);

        const std::size_t headers_start = request_line_end + 2;
        const std::size_t headers_end = string_value.find("\r\n\r\n", headers_start);
        if (headers_end == std::string_view::npos)
        {
            return false;
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
                // 移除处理好的行和换行符
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
                return false;
            }

            // 去除头字段名和值的首尾空格
            const std::string_view name = trim(line.substr(0, colon_pos));
            const std::string_view value = trim(line.substr(colon_pos + 1));

            if (name.empty())
            {
                return false;
            }

            request_instance.set(name, value);
        }

        const std::size_t body_start = headers_end + 4;
        if (body_start < string_value.size())
        {
            const std::string_view body_view = string_value.substr(body_start);
            if (!body_view.empty())
            {
                request_instance.body(body_view);
            }
        }

        const std::string_view connection_value = request_instance.at("Connection");
        if (!connection_value.empty())
        {
            if (iequals(connection_value, "keep-alive"))
            {
                request_instance.keep_alive(true);
            }
            else if (iequals(connection_value, "close"))
            {
                request_instance.keep_alive(false);
            }
        }
        else if (request_instance.version() == 11)
        {
            request_instance.keep_alive(true);
        }

        return true;
    }

    bool deserialize(const std::string_view string_value, response &response_instance)
    {
        response_instance.clear();

        // 1. 分离状态行
        const std::size_t status_line_end = string_value.find("\r\n");
        if (status_line_end == std::string_view::npos)
        {
            return false;
        }

        const std::string_view status_line = string_value.substr(0, status_line_end);

        const std::size_t first_space = status_line.find(' ');
        if (first_space == std::string_view::npos)
        {
            return false;
        }

        const std::size_t second_space = status_line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos)
        {
            return false;
        }

        const std::string_view version_part = status_line.substr(0, first_space);
        const std::string_view status_code_part = status_line.substr(first_space + 1, second_space - first_space - 1);
        const std::string_view reason_part = status_line.substr(second_space + 1);

        // 2. 解析 HTTP 版本
        unsigned int version_value = 0;
        if (!parse_http_version(version_part, version_value))
        {
            return false;
        }

        // 3. 解析状态码
        unsigned int status_code_value = 0;
        if (!parse_status_code(status_code_part, status_code_value))
        {
            return false;
        }

        // 4. 设置对象属性
        response_instance.version(version_value);
        response_instance.status(status_code_value);
        response_instance.reason(reason_part);

        // 5. 解析头字段块
        const std::size_t headers_start = status_line_end + 2;
        const std::size_t headers_end = string_value.find("\r\n\r\n", headers_start);
        if (headers_end == std::string_view::npos)
        {
            return false;
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
                return false;
            }

            const std::string_view name = trim(line.substr(0, colon_pos));
            const std::string_view value = trim(line.substr(colon_pos + 1));

            if (name.empty())
            {
                return false;
            }

            response_instance.set(name, value);
        }

        // 7. 解析实体主体
        const std::size_t body_start = headers_end + 4;
        if (body_start < string_value.size())
        {
            const std::string_view body_view = string_value.substr(body_start);
            if (!body_view.empty())
            {
                response_instance.body(body_view);
            }
        }

        // 8. 兜底设置 Connection 头字段
        const std::string_view connection_value = response_instance.at("Connection");
        if (!connection_value.empty())
        {
            if (iequals(connection_value, "keep-alive"))
            {
                response_instance.keep_alive(true);
            }
            else if (iequals(connection_value, "close"))
            {
                response_instance.keep_alive(false);
            }
        }
        else if (response_instance.version() == 11)
        {
            response_instance.keep_alive(true);
        }

        return true;
    }

} // namespace ngx::protocol::http
