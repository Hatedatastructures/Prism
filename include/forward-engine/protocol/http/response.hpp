/**
 * @file response.hpp
 * @brief HTTP 响应对象
 * @details 定义了 HTTP 响应的内存结构，包含状态码、原因短语、版本、头部和负载。
 */
#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http/header.hpp>
#include <forward-engine/protocol/http/constants.hpp>

/**
 * @namespace ngx::protocol::http
 * @brief HTTP 协议实现
 * @details 包含 HTTP/1.1 协议的完整实现，支持请求/响应的序列化与反序列化。
 */
namespace ngx::protocol::http
{
    /**
     * @brief HTTP 响应容器
     * @details 该类用于表示 HTTP 响应容器，包含响应状态码、原因短语、版本号、头字段和体内容等。
     * 它与 `request` 类类似，仅作为数据的载体，不包含任何网络 IO 逻辑。
     * @see request
     */
    class response
    {
    public:
        explicit response(memory::resource_pointer mr = memory::current_resource());
        response(const response &other) = default;
        response &operator=(const response &other) = default;
        ~response() = default;

        /**
         * @brief 设置响应状态码
         * @param code 状态码枚举
         */
        void status(enum status code) noexcept;

        /**
         * @brief 获取响应状态码
         * @return enum status 状态码枚举
         */
        [[nodiscard]] enum status status() const noexcept;

        /**
         * @brief 设置响应状态码 (整数)
         * @param code 状态码整数值
         */
        void status(unsigned int code);

        /**
         * @brief 获取响应状态码 (整数)
         * @return unsigned int 状态码整数值
         */
        [[nodiscard]] unsigned int status_code() const noexcept;

        /**
         * @brief 设置原因短语
         * @param reason 原因短语字符串 (如 "OK", "Not Found")
         */
        void reason(std::string_view reason);

        /**
         * @brief 获取原因短语
         * @return std::string_view 原因短语
         */
        [[nodiscard]] std::string_view reason() const noexcept;

        /**
         * @brief 设置 HTTP 版本
         * @param value 版本号 (如 11 表示 HTTP/1.1)
         */
        void version(unsigned int value);

        /**
         * @brief 获取 HTTP 版本
         * @return unsigned int 版本号
         */
        [[nodiscard]] unsigned int version() const noexcept;

        /**
         * @brief 设置头部字段
         * @param name 字段名
         * @param value 字段值
         * @return bool 设置是否成功
         */
        bool set(std::string_view name, std::string_view value) noexcept;
        bool set(field name, std::string_view value) noexcept;

        /**
         * @brief 获取头部字段值
         * @param name 字段名
         * @return std::string_view 字段值，若不存在则返回空
         */
        [[nodiscard]] std::string_view at(std::string_view name) const noexcept;
        [[nodiscard]] std::string_view at(field name) const noexcept;

        /**
         * @brief 设置响应体
         * @param body 响应体内容
         */
        void body(std::string_view body);
        void body(memory::string &&body);

        /**
         * @brief 获取响应体
         * @return std::string_view 响应体内容
         */
        [[nodiscard]] std::string_view body() const noexcept;

        /**
         * @brief 设置 Content-Length 头
         * @param length 内容长度
         */
        void content_length(std::uint64_t length);

        /**
         * @brief 删除头部字段
         * @param name 字段名
         */
        void erase(std::string_view name) noexcept;
        void erase(field name) noexcept;
        void erase(std::string_view name, std::string_view value) noexcept;
        void erase(field name, std::string_view value) noexcept;

        /**
         * @brief 清空响应对象
         */
        void clear();

        /**
         * @brief 设置是否保持连接
         * @param value true 为保持连接
         */
        void keep_alive(bool value) noexcept;

        /**
         * @brief 检查响应是否为空
         * @return bool
         */
        [[nodiscard]] bool empty() const noexcept;

        /**
         * @brief 获取头部容器
         * @return const headers&
         */
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
