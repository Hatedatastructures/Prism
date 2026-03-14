/**
 * @file response.hpp
 * @brief HTTP 响应对象
 * @details 定义 HTTP/1.1 和 HTTP/2 响应的内存结构，包含状态码、原因短语、版本、头部和负载。
 * 该类设计为零开销数据载体，支持高效序列化与反序列化，适用于高性能代理服务器和
 * Web 服务器场景。所有字符串使用 PMR 内存池管理，避免热路径堆分配。设计严格分离数据与 IO，
 * 该类仅存储响应数据，不包含任何网络操作。默认构造创建 HTTP/1.1 200 OK 响应。
 * @note 单个 response 实例非线程安全，需外部同步。
 * @note 返回的 std::string_view 依赖对象内部存储，注意生命周期管理。
 * @warning 在热路径中避免重复头部查找，应缓存查找结果。
 * @warning 非标准状态码可能没有预定义原因短语，需显式设置。
 */
#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http/header.hpp>
#include <forward-engine/protocol/http/constants.hpp>

/**
 * @namespace ngx::protocol::http
 * @brief HTTP 协议实现命名空间
 * @details 包含 HTTP/1.1 和 HTTP/2 协议的完整实现，提供请求和响应的序列化与反序列化、
 * 协议状态机管理等功能。模块设计为无状态，仅负责数据报文的处理，不管理连接生命周期。
 */
namespace ngx::protocol::http
{
    /**
     * @class response
     * @brief HTTP 响应容器
     * @details 高性能 HTTP 响应数据容器，用于存储和操作 HTTP 响应的所有组件。
     * 数据模型包括状态行的状态码、原因短语和版本，头部集合使用 headers 容器管理键值对，
     * 响应体存储可变长度负载。所有字符串使用 memory::string 存储，支持 PMR 内存池分配。
     * 支持 HTTP/1.0、HTTP/1.1 和 HTTP/2 语义，自动管理 Content-Length 和
     * Transfer-Encoding 头部，正确处理 Connection 和 Upgrade 头部，自动状态码到原因短语映射。
     * @note 原因短语缓存避免状态码到字符串的重复转换。
     * @note 常用头部如 Content-Length 缓存计算结果。
     * @warning 单个 response 实例非线程安全，需外部同步。
     * @warning 返回的 std::string_view 依赖对象内部存储，注意使用范围。
     * @throws std::bad_alloc 当内存资源无法分配时
     */
    class response
    {
    public:
        /**
         * @brief 构造 HTTP 响应对象
         * @param mr 内存资源指针，默认为当前线程的内存资源
         * @details 创建默认的 HTTP 响应对象，初始化为 HTTP/1.1 200 OK 响应。
         * 默认状态包含状态码 status::ok、空原因短语自动映射为 OK、版本 HTTP/1.1、
         * 空头部集合、空响应体、keep_alive 为 false。
         * @throws std::bad_alloc 当内存资源无法分配初始缓冲区时
         */
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
         * @return 状态码枚举
         */
        [[nodiscard]] enum status status() const noexcept;

        /**
         * @brief 设置响应状态码
         * @param code 状态码整数值
         * @details 通过整数值设置 HTTP 响应状态码。支持标准状态码 100 到 599 及扩展状态码。
         * 内部实现会尝试将整数映射到 status 枚举，成功映射则更新枚举并自动设置对应的原因短语，
         * 映射失败则设置枚举为 status::unknown 且原因为空。
         * @note 自动映射标准状态码到预定义原因短语。
         * @note 非标准状态码需手动调用 reason() 设置原因短语。
         * @warning 状态码应在 100 到 999 范围内，超出范围视为协议错误。
         * @throws std::bad_alloc 当内存资源无法分配原因短语字符串时
         */
        void status(unsigned int code);

        /**
         * @brief 获取响应状态码整数
         * @return 状态码整数值
         */
        [[nodiscard]] unsigned int status_code() const noexcept;

        /**
         * @brief 设置原因短语
         * @param reason 原因短语字符串
         */
        void reason(std::string_view reason);

        /**
         * @brief 获取原因短语
         * @return 原因短语视图
         */
        [[nodiscard]] std::string_view reason() const noexcept;

        /**
         * @brief 设置 HTTP 版本
         * @param value 版本号，如 11 表示 HTTP/1.1
         */
        void version(unsigned int value);

        /**
         * @brief 获取 HTTP 版本
         * @return 版本号
         */
        [[nodiscard]] unsigned int version() const noexcept;

        /**
         * @brief 设置头部字段
         * @param name 字段名
         * @param value 字段值
         * @return 设置是否成功
         */
        bool set(std::string_view name, std::string_view value) noexcept;
        bool set(field name, std::string_view value) noexcept;

        /**
         * @brief 获取头部字段值
         * @param name 字段名
         * @return 字段值，若不存在则返回空
         */
        [[nodiscard]] std::string_view at(std::string_view name) const noexcept;
        [[nodiscard]] std::string_view at(field name) const noexcept;

        /**
         * @brief 设置响应体
         * @param body 响应体内容
         * @details 设置 HTTP 响应的负载数据，支持文本和二进制内容。自动管理相关头部字段：
         * 更新 Content-Length 头部为负载字节长度，如果存在 Transfer-Encoding 头部则移除，
         * 当负载为空时移除 Content-Length 头部。
         * @note 小负载使用栈缓冲区优化，避免堆分配。
         * @note 移动语义支持零复制传递已有 memory::string 对象。
         * @warning 设置响应体后，必须确保 Content-Length 或 Transfer-Encoding 头部正确。
         * @throws std::bad_alloc 当内存资源无法分配负载缓冲区时
         * @throws std::length_error 当负载大小超过实现限制时
         */
        void body(std::string_view body);
        void body(memory::string &&body);

        /**
         * @brief 获取响应体
         * @return 响应体内容视图
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
         * @details 重置响应对象到初始状态，释放所有分配的内存缓冲区。清空操作包括重置状态码为 status::ok、
         * 清空原因短语、清空所有头部字段、清空响应体、重置版本为 HTTP/1.1、设置 keep_alive 为 false。
         * @warning 清空操作非原子，多线程访问需外部同步。
         * @warning 清空操作使所有迭代器、引用和指针失效。
         */
        void clear();

        /**
         * @brief 设置是否保持连接
         * @param value true 为保持连接
         */
        void keep_alive(bool value) noexcept;

        /**
         * @brief 检查响应是否为空
         * @return 如果响应为空则返回 true
         */
        [[nodiscard]] bool empty() const noexcept;

        /**
         * @brief 获取头部容器
         * @return 头部容器的常量引用
         */
        [[nodiscard]] const headers &header() const noexcept;
        [[nodiscard]] headers &header() noexcept;

    private:
        enum status status_
        {
            status::ok
        };
        memory::string reason_;
        memory::string body_;
        headers headers_;
        unsigned int version_{11};
        bool keep_alive_{false};
    };
}
