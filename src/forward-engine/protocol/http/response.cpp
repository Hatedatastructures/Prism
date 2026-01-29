#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/header.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <charconv>

namespace ngx::protocol::http
{
    namespace
    {
        [[nodiscard]] auto to_string(const enum status code) noexcept
            -> std::string_view
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

        [[nodiscard]] auto to_status(const unsigned int code) noexcept
            -> enum status
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

        [[nodiscard]] auto to_string(const field name) noexcept
            -> std::string_view
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

    response::response(const memory::resource_pointer mr)
        : reason_(mr), body_(mr), headers_(mr)
    {
    }

    void response::status(const enum status code) noexcept
    {
        status_ = code;
        const std::string_view reason_view = to_string(code);
        if (!reason_view.empty())
        {
            reason_.assign(reason_view.begin(), reason_view.end());
        }
    }

    auto response::status() const noexcept
        -> enum status
    {
        return status_;
    }

    void response::status(const unsigned int code)
    {
        status_ = to_status(code);
        if (const std::string_view reason_view = to_string(status_); !reason_view.empty())
        {
            reason_.assign(reason_view.begin(), reason_view.end());
        }
        else
        {
            reason_.clear();
        }
    }

    auto response::status_code() const noexcept
        -> unsigned int
    {
        return static_cast<unsigned int>(status_);
    }

    void response::reason(const std::string_view reason)
    {
        reason_.assign(reason.begin(), reason.end());
    }

    auto response::reason() const noexcept
        -> std::string_view
    {
        return reason_;
    }

    void response::version(const unsigned int value)
    {
        version_ = value;
    }

    auto response::version() const noexcept
        -> unsigned int
    {
        return version_;
    }

    auto response::set(const std::string_view name, const std::string_view value) noexcept
        -> bool
    {
        headers_.set(name, value);
        return true;
    }

    auto response::set(const field name, const std::string_view value) noexcept
        -> bool
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return false;
        }
        headers_.set(key, value);
        return true;
    }

    auto response::at(const std::string_view name) const noexcept
        -> std::string_view
    {
        return headers_.retrieve(name);
    }

    auto response::at(const field name) const noexcept
        -> std::string_view
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return {};
        }
        return headers_.retrieve(key);
    }

    void response::body(const std::string_view body)
    {
        body_.assign(body.begin(), body.end());
        content_length(body_.size());
    }

    void response::body(memory::string &&body_value)
    {
        body_ = std::move(body_value);
        content_length(body_.size());
    }

    auto response::body() const noexcept
        -> std::string_view
    {
        return body_;
    }

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

    void response::erase(const std::string_view name) noexcept
    {
        static_cast<void>(headers_.erase(name));
    }

    void response::erase(const field name) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key));
    }

    void response::erase(const std::string_view name, const std::string_view value) noexcept
    {
        static_cast<void>(headers_.erase(name, value));
    }

    void response::erase(const field name, const std::string_view value) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key, value));
    }

    void response::clear()
    {
        status_ = status::ok;
        reason_.clear();
        body_.clear();
        headers_.clear();
        version_ = 11;
        keep_alive_ = false;
    }

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

    auto response::empty() const noexcept
        -> bool
    {
        return body_.empty() && headers_.empty() && reason_.empty();
    }

    auto response::header() const noexcept
        -> const headers &
    {
        return headers_;
    }

    auto response::header() noexcept
        -> headers &
    {
        return headers_;
    }

} // namespace ngx::protocol::http
