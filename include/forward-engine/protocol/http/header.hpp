#pragma once
#include <cstddef>
#include <functional>
#include <string_view>
#include <ranges>
#include <algorithm>
#include <memory/container.hpp>
namespace ngx::protocol::http
{
    /**
     * @brief 小写字符串类
     * @details 该类用于存储和操作小写字符串。
     * 它将输入的字符串自动转换为小写，并提供了比较和哈希函数。
     */
    class downcase_string
    {
    public:
        explicit downcase_string(memory::resource_pointer mr = memory::current_resource());
        explicit downcase_string(std::string_view str, memory::resource_pointer mr = memory::current_resource());

        downcase_string(const downcase_string &other) = default;
        downcase_string &operator=(const downcase_string &other) = default;

        ~downcase_string() = default;
        bool operator==(const downcase_string &other) const;

        [[nodiscard]] const memory::string &value() const;
        [[nodiscard]] std::string_view view() const;

        struct hash
        {
            std::size_t operator()(const downcase_string &str) const
            {
                return std::hash<std::string_view>{}(str.view());
            } 
        }; // struct hash

    private:
        memory::string str_;
    }; // class downcase_string


    /**
     * @brief 头字段容器类
     * @details 该类用于存储 HTTP 请求或响应的头信息。
     * 每个头信息都由一个键值对组成，键为 downcase_string 类型，值为 std::string 类型。
     * 头信息的键在存储时会被转换为小写，以方便比较和查找。
     */
    class headers
    {
    public:
        struct header
        {
            downcase_string key;
            memory::string value;
            memory::string original_key;

            explicit header(memory::resource_pointer mr = memory::current_resource());
            header(std::string_view name, std::string_view value, memory::resource_pointer mr = memory::current_resource());
        }; // struct header

        using size_type = std::size_t;
        using container_type = memory::vector<header>;
        using iterator = container_type::const_iterator;

        explicit headers(memory::resource_pointer mr = memory::current_resource());
        headers(const headers &other) = default;
        headers &operator=(const headers &other) = default;
        ~headers() = default;

        void clear() noexcept;
        void reserve(size_type count);

        [[nodiscard]] size_type size() const noexcept;
        [[nodiscard]] bool empty() const noexcept;

        void construct(std::string_view name, std::string_view value);
        void construct(const header &entry);

        void set(std::string_view name, std::string_view value);
        bool erase(std::string_view name);
        bool erase(std::string_view name, std::string_view value);

        [[nodiscard]] bool contains(std::string_view name) const noexcept;
        [[nodiscard]] std::string_view retrieve(std::string_view name) const noexcept;

        [[nodiscard]] iterator begin() const;
        [[nodiscard]] iterator end() const;

    private:
        [[nodiscard]] memory::resource_pointer resource() const noexcept;
        [[nodiscard]] downcase_string make_key(std::string_view name) const;

        container_type entries_;
    }; // class headers
}
