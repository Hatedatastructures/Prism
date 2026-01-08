#include <http/serialization.hpp>

namespace ngx::http
{
    namespace
    {
        /**
         * @brief 将版本号转换为字符串
         * @param out 输出字符串
         * @param version_value 版本号
         * @details 版本号必须为 `10` 的倍数，例如 `10`, `11`, `20` 等。
         */
        void append_version_string(memory::string &out, const unsigned int version_value)
        {
            unsigned int major = version_value / 10;
            unsigned int minor = version_value % 10;

            char version_buffer[3]{};
            version_buffer[0] = static_cast<char>('0' + static_cast<char>(major));
            version_buffer[1] = '.';
            version_buffer[2] = static_cast<char>('0' + static_cast<char>(minor));
            out.append(version_buffer, 3);
        }

        /**
         * @brief 生成请求首行方法字符串
         * @details 优先使用 `request` 中缓存的 `method_string`，如果为空，则根据
         * 内部 `verb` 枚举值生成标准 `HTTP` 方法名字符串。
         * @param http_request 请求对象实例
         * @return std::string_view 方法名字符串视图
         */
        [[nodiscard]] std::string_view resolve_request_method_string(const request &http_request) noexcept
        {
            const std::string_view cached_method = http_request.method_string();
            if (!cached_method.empty())
            {
                return cached_method;
            }

            switch (http_request.method())
            {
            case verb::delete_:
                return "DELETE";
            case verb::get:
                return "GET";
            case verb::head:
                return "HEAD";
            case verb::post:
                return "POST";
            case verb::put:
                return "PUT";
            case verb::connect:
                return "CONNECT";
            case verb::options:
                return "OPTIONS";
            case verb::trace:
                return "TRACE";
            case verb::patch:
                return "PATCH";
            default:
                return "UNKNOWN";
            }
        }

        /**
         * @brief 生成响应首行原因字符串
         * @details 优先使用 `response` 中缓存的 `reason_string`，如果为空，则根据
         * 内部 `status` 枚举值生成标准 `HTTP` 原因字符串。
         * @param http_response 响应对象实例
         * @return std::string_view 原因字符串视图
         */
        [[nodiscard]] std::string_view resolve_response_reason_view(const response &http_response) noexcept
        {
            const std::string_view reason_view = http_response.reason();
            if (!reason_view.empty())
            {
                return reason_view;
            }

            switch (http_response.status())
            {
            case status::ok:
                return "OK";
            case status::created:
                return "Created";
            case status::accepted:
                return "Accepted";
            case status::no_content:
                return "No Content";
            case status::moved_permanently:
                return "Moved Permanently";
            case status::found:
                return "Found";
            case status::see_other:
                return "See Other";
            case status::not_modified:
                return "Not Modified";
            case status::bad_request:
                return "Bad Request";
            case status::unauthorized:
                return "Unauthorized";
            case status::forbidden:
                return "Forbidden";
            case status::not_found:
                return "Not Found";
            case status::method_not_allowed:
                return "Method Not Allowed";
            case status::request_timeout:
                return "Request Timeout";
            case status::conflict:
                return "Conflict";
            case status::gone:
                return "Gone";
            case status::length_required:
                return "Length Required";
            case status::payload_too_large:
                return "Payload Too Large";
            case status::uri_too_long:
                return "URI Too Long";
            case status::unsupported_media_type:
                return "Unsupported Media Type";
            case status::range_not_satisfiable:
                return "Range Not Satisfiable";
            case status::expectation_failed:
                return "Expectation Failed";
            case status::upgrade_required:
                return "Upgrade Required";
            case status::too_many_requests:
                return "Too Many Requests";
            case status::internal_server_error:
                return "Internal Server Error";
            case status::not_implemented:
                return "Not Implemented";
            case status::bad_gateway:
                return "Bad Gateway";
            case status::service_unavailable:
                return "Service Unavailable";
            case status::gateway_timeout:
                return "Gateway Timeout";
            case status::http_version_not_supported:
                return "HTTP Version Not Supported";
            default:
                return {};
            }
        }
    } // namespace

    memory::string serialize(const request &http_request, memory::resource_pointer mr)
    {
        const std::string_view method_string = resolve_request_method_string(http_request);
        const auto &target_string = http_request.target();

        const headers &header_container = http_request.header();
        const std::string_view body_view = http_request.body();

        memory::string result(mr);
        result.reserve(128 + target_string.size() + static_cast<std::size_t>(header_container.size() * 32) + body_view.size());

        result.append(method_string.data(), method_string.size());
        result.push_back(' ');
        result.append(target_string);
        result.append(" HTTP/");
        append_version_string(result, http_request.version());
        result.append("\r\n");

        for (const auto &header_entry : header_container)
        {
            if (header_entry.value.empty())
            {
                continue;
            }

            result.append(header_entry.original_key);
            result.append(": ");
            result.append(header_entry.value);
            result.append("\r\n");
        }

        result.append("\r\n");

        if (!body_view.empty())
        {
            result.append(body_view.data(), body_view.size());
        }

        return result;
    }

    memory::string serialize(const response &http_response, memory::resource_pointer mr)
    {
        const unsigned int status_code_value = http_response.status_code();
        const std::string_view reason_view = resolve_response_reason_view(http_response);

        const headers &header_container = http_response.header();
        const std::string_view body_view = http_response.body();

        char status_buffer[4]{};
        char *status_buffer_end = status_buffer; // 手动转换状态码性能更好
        {
            unsigned int code = status_code_value;
            status_buffer_end[2] = static_cast<char>('0' + static_cast<char>(code % 10));
            code /= 10;
            status_buffer_end[1] = static_cast<char>('0' + static_cast<char>(code % 10));
            code /= 10;
            status_buffer_end[0] = static_cast<char>('0' + static_cast<char>(code % 10));
            status_buffer_end += 3;
        }

        memory::string result(mr);
        result.reserve(128 + static_cast<std::size_t>(header_container.size() * 32) + body_view.size());

        result.append("HTTP/");
        append_version_string(result, http_response.version());
        result.push_back(' ');
        result.append(status_buffer, status_buffer_end);
        result.push_back(' ');
        result.append(reason_view.data(), reason_view.size());
        result.append("\r\n");

        for (const auto &header_entry : header_container)
        {
            if (header_entry.value.empty())
            {
                continue;
            }

            result.append(header_entry.original_key);
            result.append(": ");
            result.append(header_entry.value);
            result.append("\r\n");
        }

        result.append("\r\n");

        if (!body_view.empty())
        {
            result.append(body_view.data(), body_view.size());
        }

        return result;
    }

} // namespace ngx::http
