#include <prism/protocol/http/constants.hpp>
#include <prism/protocol/http/request.hpp>
#include <charconv>

namespace psm::protocol::http
{
    namespace
    {
        [[nodiscard]] auto to_string(const verb value) noexcept
            -> std::string_view
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

        [[nodiscard]] auto string_to_verb(const std::string_view value) noexcept
            -> verb
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

        [[nodiscard]] auto to_string(const field value) noexcept
            -> std::string_view
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
            case field::proxy_authorization:
                return "Proxy-Authorization";
            default:
                return {};
            }
        }
    } // namespace

    request::request(const memory::resource_pointer mr)
        : method_string_(mr), target_(mr), body_(mr), headers_(mr)
    {
    }

    void request::method(const verb method)
    {
        method_ = method;
        const std::string_view method_name = to_string(method);
        method_string_.assign(method_name.begin(), method_name.end());
    }

    auto request::method() const noexcept
        -> verb
    {
        return method_;
    }

    void request::method(const std::string_view method)
    {
        method_string_.assign(method.begin(), method.end());
        method_ = string_to_verb(method);
    }

    auto request::method_string() const noexcept
        -> std::string_view
    {
        return method_string_;
    }

    void request::target(const std::string_view target)
    {
        target_.assign(target.begin(), target.end());
    }

    auto request::target() const noexcept
        -> const memory::string &
    {
        return target_;
    }

    void request::version(const unsigned int value)
    {
        version_ = value;
    }

    auto request::version() const noexcept
        -> unsigned int
    {
        return version_;
    }

    auto request::set(const std::string_view name, const std::string_view value) noexcept
        -> bool
    {
        headers_.set(name, value);
        return true;
    }

    auto request::set(const field name, const std::string_view value) noexcept
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

    auto request::at(const std::string_view name) const noexcept
        -> std::string_view
    {
        return headers_.retrieve(name);
    }

    auto request::at(const field name) const noexcept
        -> std::string_view
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return {};
        }
        return headers_.retrieve(key);
    }

    void request::body(const std::string_view body)
    {
        body_.assign(body.begin(), body.end());
        content_length(body_.size());
    }

    void request::body(memory::string &&body_value)
    {
        body_ = std::move(body_value);
        content_length(body_.size());
    }

    auto request::body() const noexcept
        -> std::string_view
    {
        return body_;
    }

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

    void request::erase(const std::string_view name) noexcept
    {
        static_cast<void>(headers_.erase(name));
    }

    void request::erase(const field name) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key));
    }

    void request::erase(const std::string_view name, const std::string_view value) noexcept
    {
        static_cast<void>(headers_.erase(name, value));
    }

    void request::erase(const field name, const std::string_view value) noexcept
    {
        const std::string_view key = to_string(name);
        if (key.empty())
        {
            return;
        }
        static_cast<void>(headers_.erase(key, value));
    }

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

    auto request::empty() const noexcept
        -> bool
    {
        return target_.empty() && headers_.empty() && body_.empty();
    }

    auto request::header() const noexcept
        -> const headers &
    {
        return headers_;
    }

    auto request::header() noexcept
        -> headers &
    {
        return headers_;
    }

} // namespace psm::protocol::http
