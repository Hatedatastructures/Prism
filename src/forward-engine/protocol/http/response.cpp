#include <protocol/http/response.hpp>
#include <protocol/http/header.hpp>
#include <protocol/http/constants.hpp>
#include <charconv>

namespace ngx::protocol::http
{
    namespace
    {
        [[nodiscard]] std::string_view to_string(const enum  status code) noexcept
        {
            switch (code)
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

        [[nodiscard]] enum status to_status(const unsigned int code) noexcept
        {
            switch (code)
            {
            case 200:
                return status::ok;
            case 201:
                return status::created;
            case 202:
                return status::accepted;
            case 204:
                return status::no_content;
            case 301:
                return status::moved_permanently;
            case 302:
                return status::found;
            case 303:
                return status::see_other;
            case 304:
                return status::not_modified;
            case 400:
                return status::bad_request;
            case 401:
                return status::unauthorized;
            case 403:
                return status::forbidden;
            case 404:
                return status::not_found;
            case 405:
                return status::method_not_allowed;
            case 408:
                return status::request_timeout;
            case 409:
                return status::conflict;
            case 410:
                return status::gone;
            case 411:
                return status::length_required;
            case 413:
                return status::payload_too_large;
            case 414:
                return status::uri_too_long;
            case 415:
                return status::unsupported_media_type;
            case 416:
                return status::range_not_satisfiable;
            case 417:
                return status::expectation_failed;
            case 426:
                return status::upgrade_required;
            case 429:
                return status::too_many_requests;
            case 500:
                return status::internal_server_error;
            case 501:
                return status::not_implemented;
            case 502:
                return status::bad_gateway;
            case 503:
                return status::service_unavailable;
            case 504:
                return status::gateway_timeout;
            case 505:
                return status::http_version_not_supported;
            default:
                return status::unknown;
            }
        }

        [[nodiscard]] std::string_view to_string(const field name) noexcept
        {
            switch (name)
            {
            case field::connection:
                return "Connection";
            case field::content_length:
                return "Content-Length";
            case field::content_type:
                return "Content-Type";
            case field::transfer_encoding:
                return "Transfer-Encoding";
            case field::server:
                return "Server";
            case field::date:
                return "Date";
            default:
                return {};
            }
        }
    } // namespace

    response::response(memory::resource_pointer mr)
        : reason_(mr), body_(mr), headers_(mr)
    {
    }

    /**
     * @brief 设置响应状态码
     * @details 该函数用于设置 HTTP 响应的状态码
     * @param  code 状态码枚举值
     */
    void response::status(const enum status code) noexcept
    {
        status_ = code;
        const std::string_view reason_view = to_string(code);
        if (!reason_view.empty())
        {
            reason_.assign(reason_view.begin(), reason_view.end());
        }
    }

    /**
     * @brief 获取响应状态码
     * @details 该函数用于获取 HTTP 响应的状态码
     * @return 状态码枚举值
     */
    enum status response::status() const noexcept
    {
        return status_;
    }

    /**
     * @brief 设置响应状态码
     * @details 该函数用于设置 HTTP 响应的状态码
     * @param  code 状态码枚举值
     */
    void response::status(const unsigned int code)
    {
        status_ = to_status(code);
        const std::string_view reason_view = to_string(status_);
        if (!reason_view.empty())
        {
            reason_.assign(reason_view.begin(), reason_view.end());
        }
        else
        {
            reason_.clear();
        }
    }

    /**
     * @brief 获取响应状态码
     * @details 该函数用于获取 HTTP 响应的状态码
     * @return 状态码枚举值
     */
    unsigned int response::status_code() const noexcept
    {
        return static_cast<unsigned int>(status_);
    }

    /**
     * @brief 设置响应原因短语
     * @details 该函数用于设置 HTTP 响应的原因短语
     * @param  reason_value 原因短语字符串视图
     */
    void response::reason(const std::string_view reason_value)
    {
        reason_.assign(reason_value.begin(), reason_value.end());
    }

    /**
     * @brief 获取响应原因短语
     * @details 该函数用于获取 HTTP 响应的原因短语
     * @return 原因短语字符串视图
     */
    std::string_view response::reason() const noexcept
    {
        return reason_;
    }

    /**
     * @brief 设置响应 HTTP 版本
     * @details 该函数用于设置 HTTP 响应的版本
     * @param  value HTTP 版本号
     */
    void response::version(const unsigned int value)
    {
        version_ = value;
    }

    /**
     * @brief 获取响应 HTTP 版本
     * @details 该函数用于获取 HTTP 响应的版本
     * @return HTTP 版本号
     */
    unsigned int response::version() const noexcept
    {
        return version_;
    }

    /**
     * @brief 设置响应头字段
     * @details 该函数用于设置 HTTP 响应的头字段
     * @param  name 头字段名称字符串视图
     * @param  value 头字段值字符串视图
     * @return 是否设置成功
     */
    bool response::set(const std::string_view name, const std::string_view value) noexcept
    {
        headers_.set(name, value);
        return true;
    }

    /**
     * @brief 设置响应头字段
     * @details 该函数用于设置 HTTP 响应的头字段
     * @param  name 头字段名称枚举值
     * @param  value 头字段值字符串视图
     * @return 是否设置成功
     */
    bool response::set(const field name, const std::string_view value) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return false;
        }
        headers_.set(key, value);
        return true;
    }

    /**
     * @brief 获取响应头字段值
     * @details 该函数用于获取 HTTP 响应的头字段值
     * @param  name 头字段名称字符串视图
     * @return 头字段值字符串视图
     */
    std::string_view response::at(const std::string_view name) const noexcept
    {
        return headers_.retrieve(name);
    }

    /**
     * @brief 获取响应头字段值
     * @details 该函数用于获取 HTTP 响应的头字段值
     * @param  name 头字段名称枚举值
     * @return 头字段值字符串视图
     */
    std::string_view response::at(const field name) const noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return {};
        }
        return headers_.retrieve(key);
    }

    /**
     * @brief 设置响应体
     * @details 该函数用于设置 HTTP 响应的体内容
     * @param  body_value 响应体字符串视图
     */
    void response::body(const std::string_view body_value)
    {
        body_.assign(body_value.begin(), body_value.end());
        content_length(static_cast<std::uint64_t>(body_.size()));
    }

    void response::body(memory::string &&body_value)
    {
        body_ = std::move(body_value);
        content_length(static_cast<std::uint64_t>(body_.size()));
    }

    /**
     * @brief 获取响应体
     * @details 该函数用于获取 HTTP 响应的体内容
     * @return 响应体字符串视图
     */
    std::string_view response::body() const noexcept
    {
        return body_;
    }

    /**
     * @brief 设置响应内容长度
     * @details 该函数用于设置 HTTP 响应的内容长度
     * @param  length 内容长度值
     */
    void response::content_length(const std::uint64_t length)
    {
        char buffer[32]{};
        const auto result = std::to_chars(std::begin(buffer), std::end(buffer), length);
        if (result.ec != std::errc{})
        {
            return;
        }
        const std::string_view value(buffer, static_cast<std::size_t>(result.ptr - buffer));
        headers_.set("Content-Length", value);
    }

    /**
     * @brief 删除响应头字段
     * @details 该函数用于删除 HTTP 响应的头字段
     * @param  name 头字段名称字符串视图
     */
    void response::erase(const std::string_view name) noexcept
    {
        static_cast<void>(headers_.erase(name));
    }

    /**
     * @brief 删除响应头字段
     * @details 该函数用于删除 HTTP 响应的头字段
     * @param  name 头字段名称枚举值
     */
    void response::erase(const field name) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key));
    }

    /**
     * @brief 删除响应头字段
     * @details 该函数用于删除 HTTP 响应的头字段
     * @param  name 头字段名称字符串视图
     * @param  value 头字段值字符串视图
     */
    void response::erase(const std::string_view name, const std::string_view value) noexcept
    {
        static_cast<void>(headers_.erase(name, value));
    }

    /**
     * @brief 删除响应头字段
     * @details 该函数用于删除 HTTP 响应的头字段
     * @param  name 头字段名称枚举值
     * @param  value 头字段值字符串视图
     */
    void response::erase(const field name, const std::string_view value) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key, value));
    }

    /**
     * @brief 清除响应头字段
     * @details 该函数用于清除 HTTP 响应的所有头字段，将其重置为空状态。
     */
    void response::clear()
    {
        status_ = status::ok;
        reason_.clear();
        body_.clear();
        headers_.clear();
        version_ = 11;
        keep_alive_ = false;
    }

    /**
     * @brief 设置响应保持连接状态
     * @details 该函数用于设置 HTTP 响应的保持连接状态
     * @param  value 是否保持连接状态
     */
    void response::keep_alive(const bool value) noexcept
    {
        keep_alive_ = value;
        if (value)
        {
            headers_.set("Connection", "keep-alive");
        }
        else
        {
            headers_.set("Connection", "close");
        }
    }

    /**
     * @brief 检查响应是否为空
     * @details 该函数用于检查 HTTP 响应是否为空
     * @return 如果响应为空则返回 true，否则返回 false
     */
    bool response::empty() const noexcept
    {
        return body_.empty() && headers_.empty() && reason_.empty();
    }

    /**
     * @brief 获取响应头字段容器
     * @details 该函数用于获取 HTTP 响应的头字段容器，用于直接访问和操作头字段。
     * @return 响应头字段容器引用
     */
    const headers &response::header() const noexcept
    {
        return headers_;
    }

    /**
     * @brief 获取响应头字段容器
     * @details 该函数用于获取 HTTP 响应的头字段容器，用于直接访问和操作头字段。
     */
    headers &response::header() noexcept
    {
        return headers_;
    }


} // namespace ngx::protocol::http
