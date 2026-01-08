#pragma once

#include <string_view>
#include <memory/container.hpp>
#include "constants.hpp"
#include "header.hpp"

namespace ngx::http
{
    /**
     * @brief HTTP 请求容器
     * @details 该容器用于存储 HTTP 请求的相关信息，包括请求方法、目标 URI、版本号、头字段和请求体。
     */
    class request
    {
    public:
        explicit request(memory::resource_pointer mr = memory::current_resource());
        request(const request &other) = default;
        request &operator=(const request &other) = default;
        ~request() = default;

        void method(verb method);
        [[nodiscard]] verb method() const noexcept;
        void method(std::string_view method);
        [[nodiscard]] std::string_view method_string() const noexcept;

        void target(std::string_view target);
        [[nodiscard]] const memory::string &target() const noexcept;

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
        verb method_{verb::get};
        memory::string method_string_;
        memory::string target_;
        memory::string body_;
        headers headers_;
        unsigned int version_{11};
        bool keep_alive_{false};
    };
} // namespace ngx::http
