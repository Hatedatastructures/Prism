/**
 * @file source.hpp
 * @brief TCP 连接池
 * @details 管理复用 TCP 连接，减少握手开销。连接池容器 source 类维护
 * TCP 连接池，支持连接复用。设计特性包括栈式缓存，优先复用最近使用的
 * 连接（LIFO）；僵尸检测，在复用前检查连接是否已由对端关闭；
 * 线程隔离，每个线程独享一个连接池，无锁设计。
 * @note 连接池设计为线程局部使用，不支持跨线程共享。
 * @warning 必须确保 io_context 在 source 生命周期内保持运行。
 */
#pragma once

#include <array>
#include <memory>
#include <chrono>
#include <cstddef>
#include <boost/asio.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::channel
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    class source;

    /**
     * @struct endpoint_key
     * @brief 端点键
     * @details 用于唯一标识一个 TCP 端点（IP 地址 + 端口号）。
     * 它是连接池缓存（unordered_map）的 Key。核心职责包括唯一标识，
     * 通过 address、family 和 port 组合唯一标识端点；哈希支持，
     * 支持 endpoint_hash 哈希函数，用于哈希表查找；比较支持，
     * 支持默认比较运算符，用于哈希表键比较。字段说明包括 port 端口号
     *（16 位无符号整数），family 协议族（4 表示 IPv4，6 表示 IPv6），
     * address 地址数据（IPv6 使用全部 16 字节，IPv4 使用前 4 字节）。
     * @note 支持 IPv4 和 IPv6 两种协议族。
     * @warning address 字段必须根据 family 字段正确填充。
     */
    struct endpoint_key
    {
        std::uint16_t port = 0;
        std::uint8_t family = 0;
        std::array<unsigned char, 16> address{};

        friend bool operator==(const endpoint_key &l, const endpoint_key &r) = default;
    };

    endpoint_key make_endpoint_key(const tcp::endpoint &endpoint) noexcept;

    /**
     * @struct endpoint_hash
     * @brief 端点键哈希函数
     * @details 用于将 endpoint_key 类型的对象映射到哈希值，
     * 支持 std::unordered_map 等容器。
     */
    struct endpoint_hash
    {
        std::size_t operator()(const endpoint_key &key) const noexcept;
    };

    /**
     * @struct deleter
     * @brief 连接缓存删除器
     * @details 自定义删除器，用于将 socket 归还到连接池而不是直接析构。
     * 当 unique_sock 离开作用域时，该删除器会被调用。
     */
    struct deleter
    {
        source *pool = nullptr;
        tcp::endpoint endpoint{};
        bool has_endpoint = false;

        void operator()(tcp::socket *ptr) const;
    };

    /**
     * @brief 独占式 TCP 连接智能指针
     * @details 用于管理 TCP 连接的生命周期，确保在不再需要时及时关闭连接。
     * 每个连接只能被一个 unique_sock 实例持有，防止并发访问问题。
     */
    using unique_sock = std::unique_ptr<tcp::socket, deleter>;

    /**
     * @class source
     * @brief 连接缓存容器（Connection Pool）
     * @details 维护一个到目标服务器的 TCP 连接池，支持复用以降低延迟。
     * 该类是传输层的核心组件，用于管理 TCP 连接的生命周期和复用。
     * 核心机制包括栈式缓存，优先复用最近使用的连接（LIFO），
     * 提高缓存命中率；僵尸检测，在复用前检查连接是否已由对端关闭，
     * 避免使用无效连接；线程隔离，每个线程独享一个连接池，
     * 无锁设计，性能极致。
     */
    class source
    {
        struct idle_item
        {
            tcp::socket *socket = nullptr;
            std::chrono::steady_clock::time_point last_used;
        };

    public:
        /**
         * @brief 构造连接池
         * @param ioc IO 上下文，用于异步操作
         * @param resource 内存资源指针（通常为线程局部池）
         * @param max_cache_per_endpoint 单个目标端点最大缓存连接数
         * @param max_idle_seconds 空闲连接最大存活时间（秒）
         */
        explicit source(net::io_context &ioc, const memory::resource_pointer resource = memory::current_resource(),
                        const std::uint32_t max_cache_per_endpoint = 32U, const std::uint64_t max_idle_seconds = 30ULL)
            : ioc_(ioc), cache_(resource), max_cache_endpoint_(max_cache_per_endpoint),
              max_idle_time_(std::chrono::seconds(max_idle_seconds)) {}

        ~source()
        {
            clear();
        }

        source(const source &) = delete;
        source &operator=(const source &) = delete;

        /**
         * @brief 获取一个 TCP 连接
         * @param endpoint 目标端点
         * @return unique_sock 获取到的连接（包装在 unique_ptr 中）
         */
        [[nodiscard]] auto acquire_tcp(tcp::endpoint endpoint) -> net::awaitable<unique_sock>;

        /**
         * @brief 归还连接（内部接口）
         * @param s socket 指针
         */
        void recycle(tcp::socket *s);

        /**
         * @brief 归还连接（内部接口，带端点信息）
         * @param s socket 指针
         * @param endpoint 关联端点
         */
        void recycle(tcp::socket *s, const tcp::endpoint &endpoint);

    private:
        /**
         * @brief 僵尸连接检测
         * @param s socket 指针
         * @return bool 连接是否有效
         */
        [[nodiscard]] static bool zombie_detection(const tcp::socket *s);

        /**
         * @brief 清理所有缓存连接
         */
        void clear();

    private:
        net::io_context &ioc_;
        memory::unordered_map<endpoint_key, memory::vector<idle_item>, endpoint_hash> cache_;
        const std::uint32_t max_cache_endpoint_ = 64;
        const std::chrono::seconds max_idle_time_{30};
    };
}
