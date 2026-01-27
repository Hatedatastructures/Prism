#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http/header.hpp>
#include <forward-engine/protocol/http/constants.hpp>

namespace ngx::protocol::http
{
    /**
     * @brief HTTP 响应容器
     * @details 该类用于表示 HTTP 响应容器，包含响应状态码、原因短语、版本号、头字段和体内容等。
     */
    class response
    {
    public:
        explicit response(memory::resource_pointer mr = memory::current_resource());
        response(const response &other) = default;
        response &operator=(const response &other) = default;
        ~response() = default;

        void status(enum status code) noexcept;
        [[nodiscard]] enum status status() const noexcept;
        void status(unsigned int code);
        [[nodiscard]] unsigned int status_code() const noexcept;

        void reason(std::string_view reason);
        [[nodiscard]] std::string_view reason() const noexcept;

        void version(unsigned int value);
        [[nodiscard]] unsigned int version() const noexcept;

        bool set(std::string_view name, std::string_view value) noexcept;
        bool set(field name, std::string_view value) noexcept;

        [[nodiscard]] std::string_view at(std::string_view name) const noexcept;
        [[nodiscard]] std::string_view at(field name) const noexcept;

        void body(std::string_view body);
        void body(memory::string &&body);
        [[nodiscard]] std::string_view body() const noexcept;

        void content_length(std::uint64_t length);

        void erase(std::string_view name) noexcept;
        void erase(field name) noexcept;
        void erase(std::string_view name, std::string_view value) noexcept;
        void erase(field name, std::string_view value) noexcept;

        void clear();
        void keep_alive(bool value) noexcept;
        [[nodiscard]] bool empty() const noexcept;
        [[nodiscard]] const headers &header() const noexcept;
        [[nodiscard]] headers &header() noexcept;

    private:
        enum status status_{status::ok};
        memory::string reason_;
        memory::string body_;
        headers headers_;
        unsigned int version_{11};
        bool keep_alive_{false};
    };
} // namespace ngx::protocol::http
