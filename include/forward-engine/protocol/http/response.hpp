/**
 * @file response.hpp
 * @brief HTTP 响应对象
 * @details 定义了 HTTP/1.1 和 HTTP/2 响应的内存结构，包含状态码、原因短语、版本、头部和负载。
 * 该类设计为零开销数据载体，支持高效序列化与反序列化，适用于高性能代理服务器和 Web 服务器场景。
 *
 * 核心特性：
 * - 内存高效：使用 `PMR` 内存池管理所有字符串，避免热路径堆分配
 * - 零拷贝设计：内部使用 `std::string_view` 和 `memory::string` 避免数据复制
 * - 状态码智能管理：支持枚举 (`status`) 和整数双重表示，自动映射原因短语
 * - 头部优化：使用 `headers` 容器实现常量时间查找和大小写不敏感匹配
 * - 协议兼容：支持 HTTP/1.0、HTTP/1.1 和 HTTP/2 语义
 *
 * @note 设计原则：
 * - 严格分离数据与 IO：该类仅存储响应数据，不包含任何网络操作
 * - 线程安全限制：实例非线程安全，应在单个线程或协程内使用
 * - 移动语义优化：支持高效移动构造和移动赋值，避免深层复制
 * - 默认状态合理：默认构造创建 HTTP/1.1 200 OK 响应
 *
 * @warning 性能关键：在热路径中避免重复头部查找，应缓存查找结果
 * @warning 内存生命周期：`std::string_view` 返回值依赖底层存储，注意生命周期管理
 * @warning 状态码映射：非标准状态码可能没有预定义原因短语，需显式设置
 *
 * ```
 * // 创建 HTTP 响应示例
 * #include <forward-engine/protocol/http/response.hpp>
 * #include <forward-engine/memory/pool.hpp>
 *
 * using namespace ngx::protocol::http;
 *
 * // 使用线程本地内存池
 * auto pool = memory::global_pool();
 * response resp(pool->resource());
 *
 * // 设置响应属性
 * resp.status(status::ok);
 * resp.reason("OK");
 * resp.version(11); // HTTP/1.1
 *
 * // 设置头部
 * resp.set(field::content_type, "application/json");
 * resp.set(field::server, "ForwardEngine/1.0");
 * resp.set(field::cache_control, "no-cache");
 *
 * // 设置响应体
 * resp.body(R"({"status": "success", "data": {}})");
 *
 * // 获取响应信息
 * auto status = resp.status(); // status::ok
 * auto reason = resp.reason(); // "OK"
 * auto content_type = resp.at(field::content_type); // "application/json"
 *
 * // 序列化为字节流（实际实现需调用序列化函数）
 * // std::vector<std::byte> buffer = serialize(resp);
 *
 */
#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http/header.hpp>
#include <forward-engine/protocol/http/constants.hpp>

/**
 * @namespace ngx::protocol::http
 * @brief HTTP 协议实现命名空间
 * @details 包含 HTTP/1.1 和 HTTP/2 协议的完整实现，提供：
 * @details - 请求/响应的序列化与反序列化
 * @details - 协议状态机管理
 * @details - 流控与优先级处理（HTTP/2）
 * @details - 头部压缩（HPACK）
 *
 * @note 该模块设计为无状态，仅负责数据报文的处理，不管理连接生命周期
 * @warning 内存管理：协议处理器使用 `PMR` 内存池，确保零堆分配热路径
 */
namespace ngx::protocol::http
{
    /**
     * @class response
     * @brief HTTP 响应容器
     * @details 高性能 HTTP 响应数据容器，用于存储和操作 HTTP 响应的所有组件。
     * 该类设计为协议处理的核心数据结构，支持零开销内存管理和高效数据访问。
     *
     * 数据模型：
     * - 状态行：状态码 (`status`)、原因短语 (`reason`)、版本 (`version`)
     * - 头部集合：使用 `headers` 容器管理键值对，支持快速查找和修改
     * - 响应体：可变长度负载，支持文本和二进制数据
     * - 连接状态：保持连接 (`keep_alive`) 标志，用于连接复用优化
     *
     * 内存管理：
     * - 所有字符串使用 `memory::string` 存储，支持 `PMR` 内存池分配
     * - 头部容器使用定制哈希表，针对 HTTP 头部访问模式优化
     * - 移动语义避免深层复制，支持高效响应传递和转发
     *
     * 协议特性：
     * - 支持 HTTP/1.0、HTTP/1.1 和 HTTP/2 语义
     * - 自动管理 `Content-Length` 和 `Transfer-Encoding` 头部
     * - 正确处理 `Connection: keep-alive` 和 `Upgrade` 头部
     * - 支持分块传输编码（通过外部处理器）
     * - 自动状态码到原因短语映射
     *
     * @note 性能优化：
     * - 原因短语缓存：避免状态码到字符串的重复转换
     * - 头部预计算：常用头部（如 `Content-Length`）缓存计算结果
     * - 小字符串优化：短字符串使用栈存储，避免堆分配
     * - 默认响应优化：200 OK 响应使用静态存储，避免分配
     *
     * @warning 线程安全：单个 `response` 实例非线程安全，需外部同步
     * @warning 生命周期：返回的 `std::string_view` 依赖对象内部存储，注意使用范围
     * @warning 状态码合规：确保状态码与原因短语匹配，避免协议错误
     *
     * ```
     * // 高级使用示例：响应构建和修改
     * #include <forward-engine/protocol/http/response.hpp>
     *
     * using namespace ngx::protocol::http;
     *
     * // 创建并配置复杂响应
     * response resp;
     *
     * // 设置基本属性
     * resp.status(status::created); // 201 Created
     * resp.reason("Created");
     * resp.version(11);
     *
     * // 批量设置头部
     * resp.set(field::content_type, "application/json");
     * resp.set(field::location, "/api/data/123");
     * resp.set(field::server, "ForwardEngine/1.0");
     * resp.set("X-Custom-Header", "custom-value"); // 自定义头部
     *
     * // 管理连接状态
     * resp.keep_alive(true); // 自动设置 Connection: keep-alive
     *
     * // 设置响应体
     * resp.body(R"({"id": 123, "status": "created"})");
     *
     * // 检查头部
     * if (resp.at(field::content_type) == "application/json") {
     *     // 处理 JSON 响应
     * }
     *
     * // 清空响应（重用对象）
     * resp.clear();
     *
     *
     */
    class response
    {
    public:
        /**
         * @brief 构造 HTTP 响应对象
         * @param mr 内存资源指针，默认为当前线程的内存资源
         * @details 创建默认的 HTTP 响应对象，初始化为 HTTP/1.1 200 OK 响应。
         * 默认状态包含：
         * - 状态码：`status::ok` (200)
         * - 原因短语：空字符串（自动映射为 "OK"）
         * - 版本：HTTP/1.1 (11)
         * - 空头部集合
         * - 空响应体
         * - `keep_alive`：`false`
         *
         * @note 内存管理：
         * - 传入 `PMR` 内存资源指针，控制对象内部所有分配行为
         * - 使用 `memory::current_resource()` 获取当前线程内存池
         * - 推荐在生产环境中使用预分配内存池，避免热路径堆分配
         *
         * @warning 性能关键：在热路径中避免重复构造，应重用现有对象
         * @throws `std::bad_alloc` 当内存资源无法分配初始缓冲区时
         *
         * ```
         * // 构造示例
         * #include <forward-engine/protocol/http/response.hpp>
         * #include <forward-engine/memory/pool.hpp>
         *
         * using namespace ngx::protocol::http;
         *
         * // 使用默认内存资源（当前线程池）
         * response resp1; // HTTP/1.1 200 OK
         *
         * // 使用特定内存池
         * auto pool = memory::global_pool();
         * response resp2(pool->resource());
         *
         * // 使用无内存分配的资源（栈分配）
         * std::array<std::byte, 4096> buffer;
         * memory::monotonic_resource mr(buffer.data(), buffer.size());
         * response resp3(&mr);
         *
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
         * @return enum status 状态码枚举
         */
        [[nodiscard]] enum status status() const noexcept;

        /**
         * @brief 设置响应状态码 (整数)
         * @param code 状态码整数值
         * @details 通过整数值设置 HTTP 响应状态码。支持标准状态码（100-599）及扩展状态码。
         * 内部实现会尝试将整数映射到 `status` 枚举：
         * - 成功映射：更新 `status_` 枚举，自动设置对应的原因短语
         * - 映射失败：设置 `status_` 为 `status::unknown`，原因短语为空
         *
         * @note 自动映射：标准状态码自动设置预定义原因短语（如 200 → "OK"）
         * @note 扩展支持：非标准状态码保留整数值，原因短语需显式设置
         *
         * @warning 协议合规：状态码应在 100-999 范围内，超出范围视为协议错误
         * @warning 原因短语：非标准状态码需手动调用 `reason()` 设置原因短语
         * @throws `std::bad_alloc` 当内存资源无法分配原因短语字符串时
         * @throws `std::invalid_argument` 当状态码超出有效范围时（如有验证）
         *
         * ```
         * // 整数状态码设置示例
         * response resp;
         *
         * // 标准状态码
         * resp.status(200); // 自动设置 status::ok, reason="OK"
         * resp.status(404); // 自动设置 status::not_found, reason="Not Found"
         * resp.status(500); // 自动设置 status::internal_server_error, reason="Internal Server Error"
         *
         * // 扩展状态码
         * resp.status(418); // status::im_a_teapot (如果枚举包含)
         * resp.status(999); // status::unknown, reason=""
         *
         * // 显式设置非标准状态码的原因短语
         * resp.status(499); // 自定义状态码
         * resp.reason("Client Closed Request"); // Nginx 自定义状态码
         *
         * // 验证设置结果
         * auto enum_val = resp.status(); // 获取枚举值
         * auto int_val = resp.status_code(); // 获取整数值
         * auto reason_val = resp.reason(); // 获取原因短语
         *
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
         * @details 设置 HTTP 响应的负载数据。支持文本和二进制内容。
         * 自动管理相关头部字段：
         * - 更新 `Content-Length` 头部为负载字节长度
         * - 如果存在 `Transfer-Encoding` 头部，则移除（分块编码由外部处理）
         * - 当负载为空时，移除 `Content-Length` 头部
         *
         * @note 内存管理：
         * - `std::string_view` 版本：复制数据到内部 `memory::string` 缓冲区
         * - `memory::string&&` 版本：移动数据，避免深层复制
         * - 使用对象的 `PMR` 内存资源进行分配
         *
         * @note 性能优化：
         * - 小负载使用栈缓冲区优化，避免堆分配
         * - 移动语义支持零复制传递已有 `memory::string` 对象
         * - 内部缓冲区预分配，减少重复设置时的重新分配
         *
         * @warning 协议合规：设置响应体后，必须确保 `Content-Length` 或 `Transfer-Encoding` 头部正确
         * @warning 大负载处理：超大负载（>4MB）应考虑流式处理，避免内存压力
         * @throws `std::bad_alloc` 当内存资源无法分配负载缓冲区时
         * @throws `std::length_error` 当负载大小超过实现限制时（如有）
         *
         * ```
         * // 响应体设置示例
         * response resp;
         *
         * // 设置文本负载
         * resp.body("Hello, World!");
         * // 自动设置 Content-Length: 13
         *
         * // 设置 JSON 负载
         * resp.body(R"({"status": "ok", "data": {}})");
         *
         * // 设置 HTML 负载
         * resp.body("<html><body><h1>Welcome</h1></body></html>");
         *
         * // 设置二进制负载（通过 string_view）
         * std::vector<std::byte> binary_data = load_binary_file();
         * resp.body(std::string_view(
         *     reinterpret_cast<const char*>(binary_data.data()),
         *     binary_data.size()
         * ));
         *
         * // 移动现有 memory::string
         * memory::string large_data = load_large_data();
         * resp.body(std::move(large_data)); // 零复制移动
         *
         * // 获取设置后的内容长度
         * auto content_length = resp.at(field::content_length);
         * // 返回 "123"（负载长度字符串）
         *
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
         * @details 重置响应对象到初始状态，释放所有分配的内存缓冲区。
         * 清空操作包括：
         * - 重置状态码为 `status::ok` (200)
         * - 清空原因短语
         * - 清空所有头部字段
         * - 清空响应体
         * - 重置版本为 HTTP/1.1 (11)
         * - 设置 `keep_alive` 为 `false`
         *
         * @note 内存管理：
         * - 释放内部字符串缓冲区内存，但保留内存资源引用
         * - 清空后对象可立即重用，避免重复构造开销
         * - 头部容器保持初始容量，避免重复分配
         *
         * @note 性能优化：
         * - 清空操作不释放内存资源本身，仅释放分配的缓冲区
         * - 适合响应对象重用场景，如连接池中的持久连接
         * - 比析构后重新构造更高效
         *
         * @warning 线程安全：清空操作非原子，多线程访问需外部同步
         * @warning 迭代器失效：清空操作使所有迭代器、引用和指针失效
         *
         * ```
         * // 清空和重用示例
         * response resp;
         *
         * // 配置完整响应
         * resp.status(status::created);
         * resp.reason("Created");
         * resp.set(field::content_type, "application/json");
         * resp.set(field::location, "/api/v1/data");
         * resp.body(R"({"id": 123})");
         *
         * // 使用响应...
         * send_response(resp);
         *
         * // 清空并重用
         * resp.clear();
         *
         * // 现在 resp 恢复到初始状态 (200 OK)
         * assert(resp.status() == status::ok);
         * assert(resp.reason().empty()); // 自动映射为 "OK"
         * assert(resp.body().empty());
         *
         * // 配置新响应
         * resp.status(status::not_found);
         * resp.reason("Not Found");
         * // ... 继续使用
         *
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
} // namespace ngx::protocol::http
