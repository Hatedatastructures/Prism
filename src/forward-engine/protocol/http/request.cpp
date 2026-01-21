#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/protocol/http/request.hpp>
#include <charconv>

namespace ngx::protocol::http
{
    namespace
    {
        [[nodiscard]] std::string_view to_string(const verb value) noexcept
        {
            switch (value)
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
        [[nodiscard]] verb string_to_verb(const std::string_view value) noexcept
        {
            if (value == "DELETE")
            {
                return verb::delete_;
            }
            if (value == "GET")
            {
                return verb::get;
            }
            if (value == "HEAD")
            {
                return verb::head;
            }
            if (value == "POST")
            {
                return verb::post;
            }
            if (value == "PUT")
            {
                return verb::put;
            }
            if (value == "CONNECT")
            {
                return verb::connect;
            }
            if (value == "OPTIONS")
            {
                return verb::options;
            }
            if (value == "TRACE")
            {
                return verb::trace;
            }
            if (value == "PATCH")
            {
                return verb::patch;
            }
            return verb::unknown;
        }

        [[nodiscard]] std::string_view to_string(const field value) noexcept
        {
            switch (value)
            {
            case field::host:
                return "Host";
            case field::user_agent:
                return "User-Agent";
            case field::connection:
                return "Connection";
            case field::accept:
                return "Accept";
            case field::accept_encoding:
                return "Accept-Encoding";
            case field::accept_language:
                return "Accept-Language";
            case field::content_length:
                return "Content-Length";
            case field::content_type:
                return "Content-Type";
            case field::transfer_encoding:
                return "Transfer-Encoding";
            default:
                return {};
            }
        }
    } // namespace

    request::request(memory::resource_pointer mr)
        : method_string_(mr), target_(mr), body_(mr), headers_(mr)
    {
    }

    /**
     * @brief 设置请求方法
     * @details 该函数用于设置 HTTP 请求的方法
     * @param  method_value 请求方法枚举值
     */
    void request::method(const verb method_value)
    {
        method_ = method_value;
        const std::string_view method_name = to_string(method_value);
        method_string_.assign(method_name.begin(), method_name.end());
    }

    /**
     * @brief 获取请求方法
     * @details 该函数用于获取 HTTP 请求的方法
     * @return 请求方法枚举值
     */
    verb request::method() const noexcept
    {
        return method_;
    }

    /**
     * @brief 设置请求方法
     * @details 该函数用于设置 HTTP 请求的方法
     * @param  method_value 请求方法字符串视图
     */
    void request::method(const std::string_view method_value)
    {
        method_string_.assign(method_value.begin(), method_value.end());
        method_ = string_to_verb(method_value);
    }

    /**
     * @brief 获取请求方法字符串视图
     * @details 该函数用于获取 HTTP 请求的方法字符串视图
     * @return 请求方法字符串视图
     */
    std::string_view request::method_string() const noexcept
    {
        return method_string_;
    }

    /**
     * @brief 设置请求目标 URI
     * @details 该函数用于设置 HTTP 请求的目标 URI，包括路径和查询参数。
     * @param  target_value 请求目标 URI 字符串视图
     */
    void request::target(const std::string_view target_value)
    {
        target_.assign(target_value.begin(), target_value.end());
    }

    /**
     * @brief 获取请求目标 URI
     * @details 该函数用于获取 HTTP 请求的目标 URI，包括路径和查询参数。
     * @return 请求目标 URI 字符串引用
     */
    const memory::string &request::target() const noexcept
    {
        return target_;
    }

    /**
     * @brief 设置 HTTP 版本
     * @details 该函数用于设置 HTTP 请求的版本
     * @param  value HTTP 版本号
     */
    void request::version(const unsigned int value)
    {
        version_ = value;
    }

    /**
     * @brief 获取 HTTP 版本
     * @details 该函数用于获取 HTTP 请求的版本
     * @return HTTP 版本号
     */
    unsigned int request::version() const noexcept
    {
        return version_;
    }

    /**
     * @brief 设置请求头字段
     * @details 该函数用于设置 HTTP 请求的头字段
     * @param  name 头字段名称字符串视图
     * @param  value 头字段值字符串视图
     * @return 是否设置成功
     */
    bool request::set(const std::string_view name, const std::string_view value) noexcept
    {
        headers_.set(name, value);
        return true;
    }

    /**
     * @brief 设置请求头字段
     * @details 该函数用于设置 HTTP 请求的头字段
     * @param  name 头字段名称枚举值
     * @param  value 头字段值字符串视图
     * @return 是否设置成功
     */
    bool request::set(const field name, const std::string_view value) noexcept
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
     * @brief 获取请求头字段值
     * @details 该函数用于获取 HTTP 请求的头字段值
     * @param  name 头字段名称字符串视图
     * @return 头字段值字符串视图
     */
    std::string_view request::at(const std::string_view name) const noexcept
    {
        return headers_.retrieve(name);
    }

    /**
     * @brief 获取请求头字段值
     * @details 该函数用于获取 HTTP 请求的头字段值
     * @param  name 头字段名称枚举值
     * @return 头字段值字符串视图
     */
    std::string_view request::at(const field name) const noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return {};
        }
        return headers_.retrieve(key);
    }

    /**
     * @brief 设置请求体
     * @details 该函数用于设置 HTTP 请求的请求体
     * @param  body_value 请求体字符串视图
     */
    void request::body(const std::string_view body_value)
    {
        body_.assign(body_value.begin(), body_value.end());
        content_length(static_cast<std::uint64_t>(body_.size()));
    }

    void request::body(memory::string &&body_value)
    {
        body_ = std::move(body_value);
        content_length(static_cast<std::uint64_t>(body_.size()));
    }

    /**
     * @brief 获取请求体
     * @details 该函数用于获取 HTTP 请求的请求体
     * @return 请求体字符串视图
     */
    std::string_view request::body() const noexcept
    {
        return body_;
    }

    /**
     * @brief 设置请求内容长度
     * @details 该函数用于设置 HTTP 请求的内容长度
     * @param  length 内容长度值
     */
    void request::content_length(const std::uint64_t length)
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
     * @brief 删除请求头字段
     * @details 该函数用于删除 HTTP 请求的头字段
     * @param  name 头字段名称字符串视图
     */
    void request::erase(const std::string_view name) noexcept
    {
        static_cast<void>(headers_.erase(name));
    }

    /**
     * @brief 删除请求头字段
     * @details 该函数用于删除 HTTP 请求的头字段
     * @param  name 头字段名称枚举值
     */
    void request::erase(const field name) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key));
    }

    /**
     * @brief 删除请求头字段
     * @details 该函数用于删除 HTTP 请求的头字段
     * @param  name 头字段名称字符串视图
     * @param  value 头字段值字符串视图
     */
    void request::erase(const std::string_view name, const std::string_view value) noexcept
    {
        static_cast<void>(headers_.erase(name, value));
    }

    /**
     * @brief 删除请求头字段
     * @details 该函数用于删除 HTTP 请求的头字段
     * @param  name 头字段名称枚举值
     * @param  value 头字段值字符串视图
     */
    void request::erase(const field name, const std::string_view value) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key, value));
    }

    /**
     * @brief 清除请求头字段
     * @details 该函数用于清除 HTTP 请求的所有头字段
     */
    void request::clear()
    {
        method_ = verb::get;
        method_string_.clear();
        target_.clear();
        body_.clear();
        headers_.clear();
        version_ = 11;
        keep_alive_ = false;
    }

    /**
     * @brief 设置是否保持连接
     * @details 该函数用于设置 HTTP 请求是否保持连接，用于指定是否在请求完成后保持连接。
     */
    void request::keep_alive(const bool value) noexcept
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
     * @brief 检查请求是否为空
     * @details 该函数用于检查 HTTP 请求是否为空，包括目标、头字段和请求体是否为空。
     * @return 如果请求为空则返回 true，否则返回 false
     */
    bool request::empty() const noexcept
    {
        return target_.empty() && headers_.empty() && body_.empty();
    }

    /**
     * @brief 获取请求头字段
     * @details 该函数用于获取 HTTP 请求的头字段
     * @return 请求头字段对象常量引用
     */
    const headers &request::header() const noexcept
    {
        return headers_;
    }

    /**
     * @brief 获取请求头字段
     * @details 该函数用于获取 HTTP 请求的头字段
     * @return 请求头字段对象引用
     */
    headers &request::header() noexcept
    {
        return headers_;
    }

} // namespace ngx::protocol::http
