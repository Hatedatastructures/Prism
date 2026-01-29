/**
 * @file request.hpp
 * @brief HTTP 请求对象
 * @details 定义了 HTTP 请求的内存结构，包含方法、目标、版本、头部和负载。
 */
#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/protocol/http/header.hpp>

namespace ngx::protocol::http
{
    /**
     * @class request
     * @brief HTTP 请求容器
     * @details 该容器用于存储 HTTP 请求的相关信息，包括请求方法、目标 URI、版本号、头字段和请求体。
     * 它不包含网络 IO 逻辑，仅作为数据载体。
     */
    class request
    {
    public:
        /**
         * @brief 构造 HTTP 请求对象
         * @param mr 内存资源指针，默认为当前线程的内存资源
         * @note 推荐使用 `std::pmr` 内存池以减少堆分配开销。
         */
        explicit request(memory::resource_pointer mr = memory::current_resource());
        request(const request &other) = default;
        request &operator=(const request &other) = default;
        ~request() = default;

        /**
         * @brief 设置请求方法
         * @param method 请求方法枚举
         * @details 设置方法枚举值的同时，会自动更新对应的字符串表示。
         */
        void method(verb method);

        /**
         * @brief 获取请求方法
         * @return verb 请求方法枚举
         */
        [[nodiscard]] verb method() const noexcept;

        /**
         * @brief 设置请求方法 (字符串形式)
         * @param method 请求方法字符串
         * @details 如果字符串能匹配已知的 `verb` 枚举，将同步更新枚举值；否则枚举值为 `unknown`。
         */
        void method(std::string_view method);

        /**
         * @brief 获取请求方法 (字符串形式)
         * @return std::string_view 请求方法字符串
         */
        [[nodiscard]] std::string_view method_string() const noexcept;

        /**
         * @brief 设置请求目标 URI
         * @param target 目标 URI 字符串
         * @details 通常包含路径和查询字符串 (e.g., "/index.html?q=1")，也可以是绝对 URI。
         */
        void target(std::string_view target);

        /**
         * @brief 获取请求目标 URI
         * @return const memory::string& 目标 URI
         */
        [[nodiscard]] const memory::string &target() const noexcept;

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
         * @note 字段名不区分大小写。如果字段已存在，将覆盖旧值。
         */
        bool set(std::string_view name, std::string_view value) noexcept;
        bool set(field name, std::string_view value) noexcept;

        /**
         * @brief 获取头部字段值
         * @param name 字段名
         * @return std::string_view 字段值，若不存在则返回空
         * @note 查找不区分大小写。
         */
        [[nodiscard]] std::string_view at(std::string_view name) const noexcept;
        [[nodiscard]] std::string_view at(field name) const noexcept;

        /**
         * @brief 设置请求体
         * @param body 请求体内容
         * @details 设置请求体的同时，会自动更新 `Content-Length` 头字段。
         */
        void body(std::string_view body);
        void body(memory::string &&body);

        /**
         * @brief 获取请求体
         * @return std::string_view 请求体内容
         */
        [[nodiscard]] std::string_view body() const noexcept;

        /**
         * @brief 设置 Content-Length 头
         * @param length 内容长度
         * @details 显式设置 `Content-Length` 头字段。
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
         * @brief 清空请求对象
         * @details 重置所有字段为默认状态，释放持有的内存资源（但不释放内存资源本身）。
         */
        void clear();

        /**
         * @brief 设置是否保持连接
         * @param value true 为保持连接
         * @details 根据 HTTP 版本和该设置，自动添加或修改 `Connection` 头字段。
         */
        void keep_alive(bool value) noexcept;

        /**
         * @brief 检查请求是否为空
         * @return bool
         */
        [[nodiscard]] bool empty() const noexcept;

        /**
         * @brief 获取头部容器
         * @return const headers&
         * @note 提供对底层头部容器的直接访问。
         */
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
} // namespace ngx::protocol::http
