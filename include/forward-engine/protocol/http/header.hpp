/**
 * @file header.hpp
 * @brief HTTP 头部字段容器
 * @details 定义大小写不敏感的字符串类 downcase_string 和头部字段容器 headers。
 * downcase_string 类用于存储和操作小写字符串，自动将输入字符串转换为小写，
 * 并提供比较和哈希函数，用于实现大小写不敏感的查找。headers 类用于存储
 * HTTP 请求或响应的头信息，每个头信息由键值对组成，键在存储时转换为小写
 * 以便比较和查找，同时保留原始键的大小写形式。设计遵循零开销原则，
 * 使用 PMR 内存池管理所有字符串存储，避免热路径堆分配。
 * @note 头部字段名大小写不敏感，查找时自动转换为小写进行比较。
 * @note 容器使用向量存储头部项，支持保持头部插入顺序。
 * @warning 在热路径中避免重复头部查找，应缓存查找结果。
 */
#pragma once
#include <cstddef>
#include <functional>
#include <string_view>
#include <ranges>
#include <algorithm>
#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::protocol::http
 * @brief HTTP 协议实现命名空间
 * @details 包含 HTTP/1.1 和 HTTP/2 协议的完整实现，提供请求和响应的序列化
 * 与反序列化、协议状态机管理等功能。模块设计为无状态，仅负责数据报文的
 * 处理，不管理连接生命周期。
 */
namespace ngx::protocol::http
{
    /**
     * @class downcase_string
     * @brief 小写字符串类
     * @details 用于存储和操作小写字符串的辅助类。将输入字符串自动转换为小写，
     * 提供相等比较和哈希函数，用于实现大小写不敏感的查找。内部使用 memory::string
     * 存储字符串数据，支持 PMR 内存池分配。主要用于 HTTP 头部字段名的存储和比较，
     * 因为 HTTP 头部字段名大小写不敏感。通过将所有字段名统一转换为小写，
     * 可以简化比较逻辑并提高查找效率。
     * @note 字符串在构造时转换为小写，之后不再改变。
     * @note 比较操作基于小写字符串进行，确保大小写不敏感。
     * @warning 哈希值基于小写字符串计算，确保大小写不同的字符串产生相同哈希值。
     */
    class downcase_string
    {
    public:
        /**
         * @brief 构造空的小写字符串
         * @param mr 内存资源指针，默认为当前线程的内存资源
         */
        explicit downcase_string(memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 从字符串视图构造小写字符串
         * @param str 输入字符串，将被转换为小写存储
         * @param mr 内存资源指针，默认为当前线程的内存资源
         */
        explicit downcase_string(std::string_view str, memory::resource_pointer mr = memory::current_resource());

        downcase_string(const downcase_string &other) = default;
        downcase_string &operator=(const downcase_string &other) = default;

        ~downcase_string() = default;

        /**
         * @brief 相等比较运算符
         * @param other 要比较的另一个小写字符串
         * @return 如果两个字符串相等则返回 true
         */
        bool operator==(const downcase_string &other) const;

        /**
         * @brief 获取内部字符串引用
         * @return 内部小写字符串的常量引用
         */
        [[nodiscard]] auto value() const -> const memory::string &;

        /**
         * @brief 获取字符串视图
         * @return 内部小写字符串的视图
         */
        [[nodiscard]] auto view() const -> std::string_view;

        /**
         * @struct hash
         * @brief 小写字符串哈希函数对象
         * @details 用于在哈希容器中作为键的哈希函数。基于小写字符串的视图计算哈希值，
         * 确保大小写不同的字符串产生相同哈希值。
         */
        struct hash
        {
            /**
             * @brief 计算小写字符串的哈希值
             * @param str 要计算哈希值的小写字符串
             * @return 哈希值
             */
            std::size_t operator()(const downcase_string &str) const
            {
                return std::hash<std::string_view>{}(str.view());
            }
        };

    private:
        memory::string str_;
    };

    /**
     * @class headers
     * @brief 头部字段容器类
     * @details 用于存储 HTTP 请求或响应头部字段的容器。每个头部字段由键值对组成，
     * 键使用 downcase_string 存储以支持大小写不敏感查找，同时保留原始键的大小写形式。
     * 使用向量存储头部项，支持保持头部插入顺序，适用于需要按顺序处理头部的场景。
     * 容器支持高效的头部字段查找、插入、删除和遍历操作。查找操作基于小写键进行，
     * 确保大小写不敏感。插入操作会覆盖已存在的同名头部字段。
     * @note 头部字段名大小写不敏感，查找时自动转换为小写进行比较。
     * @note 容器使用向量存储，遍历时保持插入顺序。
     * @warning 查找操作的时间复杂度为线性，在头部数量较多时应考虑使用索引优化。
     */
    class headers
    {
    public:
        /**
         * @struct header
         * @brief 头部字段项
         * @details 存储单个 HTTP 头部字段的完整信息，包括小写键、值和原始键。
         * 小写键用于比较和查找，原始键保留原始大小写形式用于序列化输出。
         */
        struct header
        {
            // 小写键，用于比较和查找
            downcase_string key;
            // 头部字段值
            memory::string value;
            // 原始键，保留大小写形式
            memory::string original_key;

            /**
             * @brief 构造空的头部字段项
             * @param mr 内存资源指针，默认为当前线程的内存资源
             */
            explicit header(memory::resource_pointer mr = memory::current_resource());

            /**
             * @brief 构造头部字段项
             * @param name 头部字段名
             * @param value 头部字段值
             * @param mr 内存资源指针，默认为当前线程的内存资源
             */
            header(std::string_view name, std::string_view value, memory::resource_pointer mr = memory::current_resource());
        };

        using size_type = std::size_t;
        using container_type = memory::vector<header>;
        using iterator = container_type::const_iterator;

        /**
         * @brief 构造空的头部容器
         * @param mr 内存资源指针，默认为当前线程的内存资源
         */
        explicit headers(memory::resource_pointer mr = memory::current_resource());

        headers(const headers &other) = default;
        headers &operator=(const headers &other) = default;
        ~headers() = default;

        /**
         * @brief 清空所有头部字段
         */
        void clear() noexcept;

        /**
         * @brief 预留存储空间
         * @param count 预留的头部字段数量
         */
        void reserve(size_type count);

        /**
         * @brief 获取头部字段数量
         * @return 头部字段数量
         */
        [[nodiscard]] size_type size() const noexcept;

        /**
         * @brief 检查容器是否为空
         * @return 如果容器为空则返回 true
         */
        [[nodiscard]] bool empty() const noexcept;

        /**
         * @brief 构造并添加头部字段
         * @param name 头部字段名
         * @param value 头部字段值
         * @details 添加新的头部字段项，不检查是否已存在同名头部。
         */
        void construct(std::string_view name, std::string_view value);

        /**
         * @brief 构造并添加头部字段
         * @param entry 头部字段项
         * @details 添加新的头部字段项，不检查是否已存在同名头部。
         */
        void construct(const header &entry);

        /**
         * @brief 设置头部字段
         * @param name 头部字段名
         * @param value 头部字段值
         * @details 如果同名头部已存在则覆盖，否则添加新头部。
         */
        void set(std::string_view name, std::string_view value);

        /**
         * @brief 删除指定名称的头部字段
         * @param name 头部字段名
         * @return 如果找到并删除则返回 true
         */
        bool erase(std::string_view name);

        /**
         * @brief 删除指定名称和值的头部字段
         * @param name 头部字段名
         * @param value 头部字段值
         * @return 如果找到并删除则返回 true
         */
        bool erase(std::string_view name, std::string_view value);

        /**
         * @brief 检查是否包含指定名称的头部字段
         * @param name 头部字段名
         * @return 如果包含则返回 true
         */
        [[nodiscard]] auto contains(std::string_view name) const noexcept -> bool;

        /**
         * @brief 获取指定名称的头部字段值
         * @param name 头部字段名
         * @return 头部字段值，如果不存在则返回空视图
         */
        [[nodiscard]] auto retrieve(std::string_view name) const noexcept -> std::string_view;

        /**
         * @brief 获取起始迭代器
         * @return 指向第一个头部字段的常量迭代器
         */
        [[nodiscard]] auto begin() const -> iterator;

        /**
         * @brief 获取结束迭代器
         * @return 指向最后一个头部字段之后的常量迭代器
         */
        [[nodiscard]] auto end() const -> iterator;

    private:
        /**
         * @brief 获取内存资源指针
         * @return 内存资源指针
         */
        [[nodiscard]] memory::resource_pointer resource() const noexcept;

        /**
         * @brief 创建小写字符串键
         * @param name 头部字段名
         * @return 小写字符串键
         */
        [[nodiscard]] auto make_key(std::string_view name) const -> downcase_string;

        // 头部字段项容器
        container_type entries_;
    };
}
