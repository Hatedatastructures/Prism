/**
 * @file request.hpp
 * @brief HTTP 请求对象
 * @details 定义 HTTP/1.1 和 HTTP/2 请求的内存结构，包含方法、目标、版本、头部和负载。
 * 该类设计为零开销数据载体，支持高效序列化与反序列化，适用于高性能代理服务器场景。
 * 所有字符串使用 PMR 内存池管理，避免热路径堆分配。设计严格分离数据与 IO，
 * 该类仅存储请求数据，不包含任何网络操作。
 * @note 单个 request 实例非线程安全，需外部同步。
 * @note 返回的 std::string_view 依赖对象内部存储，注意生命周期管理。
 * @warning 在热路径中避免重复头部查找，应缓存查找结果。
 */
#pragma once

#include <string_view>
#include <prism/memory/container.hpp>
#include <prism/protocol/http/constants.hpp>
#include <prism/protocol/http/header.hpp>

namespace psm::protocol::http
{
    /**
     * @class request
     * @brief HTTP 请求容器
     * @details 高性能 HTTP 请求数据容器，用于存储和操作 HTTP 请求的所有组件。
     * 数据模型包括请求行的方法、目标和版本，头部集合使用 headers 容器管理键值对，
     * 请求体存储可变长度负载。所有字符串使用 memory::string 存储，支持 PMR 内存池分配。
     * 支持 HTTP/1.0、HTTP/1.1 和 HTTP/2 语义，自动管理 Content-Length 和
     * Transfer-Encoding 头部，正确处理 Connection 和 Upgrade 头部。
     * @note 方法字符串缓存避免枚举到字符串的重复转换。
     * @note 常用头部如 Content-Length 缓存计算结果。
     * @warning 单个 request 实例非线程安全，需外部同步。
     * @warning 返回的 std::string_view 依赖对象内部存储，注意使用范围。
     * @throws std::bad_alloc 当内存资源无法分配时
     */
    class request
    {
    public:
        /**
         * @brief 构造 HTTP 请求对象
         * @param mr 内存资源指针，默认为当前线程的内存资源
         * @details 创建空的 HTTP 请求对象，所有字段初始化为默认值。默认使用 GET 方法、
         * 空目标、HTTP/1.1 版本、无头部和空请求体。
         * @throws std::bad_alloc 当内存资源无法分配初始缓冲区时
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
         * @return 请求方法枚举
         */
        [[nodiscard]] verb method() const noexcept;

        /**
         * @brief 设置请求方法
         * @param method 请求方法字符串
         * @details 通过字符串设置请求方法。方法字符串不区分大小写，支持标准方法及扩展方法。
         * 内部实现会尝试将字符串映射到 verb 枚举，成功映射则更新枚举和字符串缓存，
         * 映射失败则设置枚举为 verb::unknown 并保存原始字符串。
         * @throws std::bad_alloc 当内存资源无法分配字符串存储时
         */
        void method(std::string_view method);

        /**
         * @brief 获取请求方法字符串
         * @return 请求方法字符串
         */
        [[nodiscard]] std::string_view method_string() const noexcept;

        /**
         * @brief 设置请求目标 URI
         * @param target 目标 URI 字符串
         * @details 通常包含路径和查询字符串，也可以是绝对 URI。
         */
        void target(std::string_view target);

        /**
         * @brief 获取请求目标 URI
         * @return 目标 URI 的常量引用
         */
        [[nodiscard]] const memory::string &target() const noexcept;

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
         * @details 字段名不区分大小写。如果字段已存在，将覆盖旧值。
         */
        bool set(std::string_view name, std::string_view value) noexcept;
        bool set(field name, std::string_view value) noexcept;

        /**
         * @brief 获取头部字段值
         * @param name 字段名
         * @return 字段值，若不存在则返回空
         * @details 查找不区分大小写。
         */
        [[nodiscard]] std::string_view at(std::string_view name) const noexcept;
        [[nodiscard]] std::string_view at(field name) const noexcept;

        /**
         * @brief 设置请求体
         * @param body 请求体内容
         * @details 设置 HTTP 请求的负载数据，支持文本和二进制内容。自动管理相关头部字段：
         * 更新 Content-Length 头部为负载字节长度，如果存在 Transfer-Encoding 头部则移除，
         * 当负载为空时移除 Content-Length 头部。
         * @throws std::bad_alloc 当内存资源无法分配负载缓冲区时
         * @throws std::length_error 当负载大小超过实现限制时
         */
        void body(std::string_view body);
        void body(memory::string &&body);

        /**
         * @brief 获取请求体
         * @return 请求体内容的视图
         */
        [[nodiscard]] std::string_view body() const noexcept;

        /**
         * @brief 设置 Content-Length 头
         * @param length 内容长度
         * @details 显式设置 Content-Length 头字段。
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
         * @details 重置请求对象到初始状态，释放所有分配的内存缓冲区。清空操作包括重置方法为 GET、
         * 清空目标字符串、清空所有头部字段、清空请求体、重置版本为 HTTP/1.1、设置 keep_alive 为 false。
         * @warning 清空操作非原子，多线程访问需外部同步。
         * @warning 清空操作使所有迭代器、引用和指针失效。
         */
        void clear();

        /**
         * @brief 设置是否保持连接
         * @param value true 为保持连接
         * @details 根据 HTTP 版本和该设置，自动添加或修改 Connection 头字段。
         */
        void keep_alive(bool value) noexcept;

        /**
         * @brief 检查请求是否为空
         * @return 如果请求为空则返回 true
         */
        [[nodiscard]] bool empty() const noexcept;

        /**
         * @brief 获取头部容器
         * @return 头部容器的常量引用
         * @details 提供对底层头部容器的直接访问。
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
}
