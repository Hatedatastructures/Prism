/**
 * @file request.hpp
 * @brief HTTP 请求对象
 * @details 定义了 HTTP/1.1 和 HTTP/2 请求的内存结构，包含方法、目标、版本、头部和负载。
 * 该类设计为零开销数据载体，支持高效序列化与反序列化，适用于高性能代理服务器场景。
 *
 * 核心特性：
 * - 内存高效：使用 `PMR` 内存池管理所有字符串，避免热路径堆分配
 * - 零拷贝设计：内部使用 `std::string_view` 和 `memory::string` 避免数据复制
 * - 类型安全：提供枚举 (`verb`) 和字符串双重接口，确保协议兼容性
 * - 头部优化：使用 `headers` 容器实现常量时间查找和大小写不敏感匹配
 *
 * @note 设计原则：
 * - 严格分离数据与 IO：该类仅存储请求数据，不包含任何网络操作
 * - 线程安全限制：实例非线程安全，应在单个线程或协程内使用
 * - 移动语义优化：支持高效移动构造和移动赋值，避免深层复制
 *
 * @warning 性能关键：在热路径中避免重复头部查找，应缓存查找结果
 * @warning 内存生命周期：`std::string_view` 返回值依赖底层存储，注意生命周期管理
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
     * @details 高性能 HTTP 请求数据容器，用于存储和操作 HTTP 请求的所有组件。
     * 该类设计为协议处理的核心数据结构，支持零开销内存管理和高效数据访问。
     *
     * 数据模型：
     * @details - 请求行：方法 (`verb`)、目标 (`target`)、版本 (`version`)
     * @details - 头部集合：使用 `headers` 容器管理键值对，支持快速查找和修改
     * @details - 请求体：可变长度负载，支持文本和二进制数据
     * @details - 连接状态：保持连接 (`keep_alive`) 标志，用于连接复用优化
     *
     * 内存管理：
     * @details - 所有字符串使用 `memory::string` 存储，支持 `PMR` 内存池分配
     * @details - 头部容器使用定制哈希表，针对 HTTP 头部访问模式优化
     * @details - 移动语义避免深层复制，支持高效请求传递和转发
     *
     * 协议特性：
     * @details - 支持 HTTP/1.0、HTTP/1.1 和 HTTP/2 语义
     * @details - 自动管理 `Content-Length` 和 `Transfer-Encoding` 头部
     * @details - 正确处理 `Connection: keep-alive` 和 `Upgrade` 头部
     * @details - 支持分块传输编码（通过外部处理器）
     *
     * @note 性能优化：
     * @details - 方法字符串缓存：避免枚举到字符串的重复转换
     * @details - 头部预计算：常用头部（如 `Content-Length`）缓存计算结果
     * @details - 小字符串优化：短字符串使用栈存储，避免堆分配
     *
     * @warning 线程安全：单个 `request` 实例非线程安全，需外部同步
     * @warning 生命周期：返回的 `std::string_view` 依赖对象内部存储，注意使用范围
     * @warning 序列化：修改请求后需重新序列化，头部顺序可能影响某些代理兼容性
     *
     * ```
     * // 高级使用示例：请求构建和修改
     * #include <forward-engine/protocol/http/request.hpp>
     *
     * using namespace ngx::protocol::http;
     *
     * // 创建并配置复杂请求
     * request req;
     *
     * // 设置基本属性
     * req.method(verb::put);
     * req.target("/api/data/123");
     * req.version(11);
     *
     * // 批量设置头部
     * req.set(field::content_type, "application/json");
     * req.set(field::accept, "application/json, text/plain");
     * req.set(field::user_agent, "ForwardEngine/1.0");
     * req.set("X-Custom-Header", "custom-value"); // 自定义头部
     *
     * // 管理连接状态
     * req.keep_alive(true); // 自动设置 Connection: keep-alive
     *
     * // 检查头部
     * if (req.at(field::content_type) == "application/json") {
     *     // 处理 JSON 请求
     * }
     *
     * // 删除头部
     * req.erase(field::user_agent);
     *
     * // 清空请求（重用对象）
     * req.clear();
     * ```
     */
    class request
    {
    public:
        /**
         * @brief 构造 HTTP 请求对象
         * @param mr 内存资源指针，默认为当前线程的内存资源
         * @details 创建空的 HTTP 请求对象，所有字段初始化为默认值。
         * 默认使用 `GET` 方法、空目标、HTTP/1.1 版本、无头部和空请求体。
         *
         * @note 内存管理：
         * @details - 传入 `PMR` 内存资源指针，控制对象内部所有分配行为
         * @details - 使用 `memory::current_resource()` 获取当前线程内存池
         * @details - 推荐在生产环境中使用预分配内存池，避免热路径堆分配
         *
         * @throws `std::bad_alloc` 当内存资源无法分配初始缓冲区时
         *
         * ```
         * // 构造示例
         * #include <forward-engine/protocol/http/request.hpp>
         * #include <forward-engine/memory/pool.hpp>
         *
         * using namespace ngx::protocol::http;
         *
         * // 使用默认内存资源（当前线程池）
         * request req1;
         *
         * // 使用特定内存池
         * auto pool = memory::global_pool();
         * request req2(pool->resource());
         *
         * // 使用无内存分配的资源（栈分配）
         * std::array<std::byte, 4096> buffer;
         * memory::monotonic_resource mr(buffer.data(), buffer.size());
         * request req3(&mr);
         * ```
         *
         * @warning 性能关键：在热路径中避免重复构造，应重用现有对象
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
         * @details 通过字符串设置请求方法。方法字符串不区分大小写，支持标准方法及扩展方法。
         * 内部实现会尝试将字符串映射到 `verb` 枚举：
         * @details - 成功映射：更新 `method_` 枚举和 `method_string_` 缓存
         * @details - 映射失败：设置 `method_` 为 `verb::unknown`，保存原始字符串
         *
         * @throws `std::bad_alloc` 当内存资源无法分配字符串存储时
         *
         * ```
         * // 字符串方法设置示例
         * request req;
         *
         * // 标准方法（不区分大小写）
         * req.method("GET");      // verb::get
         * req.method("post");     // verb::post
         * req.method("DeLeTe");   // verb::delete_
         *
         * // 扩展方法
         * req.method("PURGE");    // verb::purge (如果枚举包含)
         * req.method("CUSTOM");   // verb::unknown，字符串保存为 "CUSTOM"
         *
         * // 验证设置结果
         * auto enum_val = req.method(); // 获取枚举值
         * auto str_val = req.method_string(); // 获取字符串表示
         * ```
         *
         * @note 性能考虑：字符串比较使用大小写不敏感算法，避免临时字符串分配
         * @note 扩展支持：自定义方法字符串会原样保存，支持非标准 HTTP 扩展
         * @warning 标准化：建议使用 `verb` 枚举接口确保协议兼容性
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
         * @details 设置 HTTP 请求的负载数据。支持文本和二进制内容。
         * 自动管理相关头部字段：
         * @details - 更新 `Content-Length` 头部为负载字节长度
         * @details - 如果存在 `Transfer-Encoding` 头部，则移除（分块编码由外部处理）
         * @details - 当负载为空时，移除 `Content-Length` 头部
         *
         * @note 内存管理：
         * @details - `std::string_view` 版本：复制数据到内部 `memory::string` 缓冲区
         * @details - `memory::string&&` 版本：移动数据，避免深层复制
         * @details - 使用对象的 `PMR` 内存资源进行分配
         *
         * @throws `std::bad_alloc` 当内存资源无法分配负载缓冲区时
         * @throws `std::length_error` 当负载大小超过实现限制时（如有）
         *
         * ```
         * // 请求体设置示例
         * request req;
         *
         * // 设置文本负载
         * req.body("Hello, World!");
         * // 自动设置 Content-Length: 13
         *
         * // 设置 JSON 负载
         * req.body(R"({"id": 123, "name": "test"})");
         *
         * // 设置二进制负载（通过 string_view）
         * std::vector<std::byte> binary_data = load_binary_file();
         * req.body(std::string_view(
         *     reinterpret_cast<const char*>(binary_data.data()),
         *     binary_data.size()
         * ));
         *
         * // 移动现有 memory::string
         * memory::string large_data = load_large_data();
         * req.body(std::move(large_data)); // 零复制移动
         *
         * // 获取设置后的内容长度
         * auto content_length = req.at(field::content_length);
         * // 返回 "123"（负载长度字符串）
         * ```
         *
         * @note 性能优化：小负载使用栈缓冲区优化，避免堆分配
         * @note 性能优化：移动语义支持零复制传递已有 `memory::string` 对象
         * @note 性能优化：内部缓冲区预分配，减少重复设置时的重新分配
         * @warning 协议合规：设置请求体后，必须确保 `Content-Length` 或 `Transfer-Encoding` 头部正确
         * @warning 大负载处理：超大负载（>4MB）应考虑流式处理，避免内存压力
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
         * @details 重置请求对象到初始状态，释放所有分配的内存缓冲区。
         * 清空操作包括：
         * @details - 重置方法为 `verb::get`
         * @details - 清空目标字符串
         * @details - 清空所有头部字段
         * @details - 清空请求体
         * @details - 重置版本为 HTTP/1.1 (11)
         * @details - 设置 `keep_alive` 为 `false`
         *
         * @note 内存管理：
         * @details - 释放内部字符串缓冲区内存，但保留内存资源引用
         * @details - 清空后对象可立即重用，避免重复构造开销
         * @details - 头部容器保持初始容量，避免重复分配
         *
         * @warning 线程安全：清空操作非原子，多线程访问需外部同步
         * @warning 迭代器失效：清空操作使所有迭代器、引用和指针失效
         *
         * ```
         * // 清空和重用示例
         * request req;
         *
         * // 配置完整请求
         * req.method(verb::post);
         * req.target("/api/v1/data");
         * req.set(field::content_type, "application/json");
         * req.body(R"({"action": "update"})");
         *
         * // 使用请求...
         * process_request(req);
         *
         * // 清空并重用
         * req.clear();
         *
         * // 现在 req 恢复到初始状态
         * assert(req.method() == verb::get);
         * assert(req.target().empty());
         * assert(req.body().empty());
         *
         * // 配置新请求
         * req.method(verb::put);
         * req.target("/api/v2/resources");
         * // ... 继续使用
         * ```
         *
         * @note 性能优化：清空操作不释放内存资源本身，仅释放分配的缓冲区
         * @note 性能优化：适合请求对象重用场景，如连接池中的持久连接
         * @note 性能优化：比析构后重新构造更高效
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
