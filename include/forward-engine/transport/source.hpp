

/**
 * @file source.hpp
 * @brief TCP 连接池
 * @details 管理复用 TCP 连接，减少握手开销。
 */
#pragma once
#include <array>
#include <memory>
#include <chrono>
#include <cstddef>
#include <boost/asio.hpp>
#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::transport
 * @brief 传输层 (Data Plane)
 * @details 负责底层的数据搬运、连接管理和协议封装。
 * 它是整个代理系统的"腿"，负责跑腿送货，但不决定送去哪里（那是 Agent 层的职责）。
 */
namespace ngx::transport
{

    namespace net = boost::asio;

    using tcp = boost::asio::ip::tcp;

    class source;

    /**
     * @brief 端点键
     * @details 用于唯一标识一个 TCP 端点 (IP 地址 + 端口号)。
     * 它是连接池缓存 (`unordered_map`) 的 Key。
     * @note 支持 IPv4 和 IPv6。
     */
    struct endpoint_key
    {
        std::uint16_t port = 0; // 端口号
        std::uint8_t family = 0; // 协议族 (4 for IPv4, 6 for IPv6)
        std::array<unsigned char, 16> address{}; // 地址数据 (IPv6 使用全部 16 字节，IPv4 使用前 4 字节)

        friend bool operator==(const endpoint_key &l, const endpoint_key &r) = default;
    };

    inline endpoint_key make_endpoint_key(const tcp::endpoint &endpoint) noexcept;

    /**
     * @brief 端点键哈希函数
     * @details 用于将 `endpoint_key` 类型的对象映射到哈希值，支持 `std::unordered_map` 等容器。
     */
    struct endpoint_hash
    {
        std::size_t operator()(const endpoint_key &key) const noexcept;
    };

    /**
     * @brief 连接缓存删除器
     * @details 自定义删除器，用于将 socket 归还到连接池而不是直接析构。
     * @note 当 `unique_sock` 离开作用域时，该删除器会被调用。
     */
    struct deleter
    {
        source *pool = nullptr; // 连接池指针
        tcp::endpoint endpoint{}; // 对应的端点
        bool has_endpoint = false; // 是否有关联端点
        void operator()(tcp::socket *ptr) const;
    }; // class deleter

    /**
     * @brief 独占式 TCP 连接智能指针
     * @details 用于管理 TCP 连接的生命周期，确保在不再需要时及时关闭连接。
     * @note 每个连接只能被一个 `unique_sock` 实例持有，防止并发访问问题。
     */
    using unique_sock = std::unique_ptr<tcp::socket, deleter>;

    /**
     * @class source
     * @brief 连接缓存容器 (Connection Pool)
     * @details 维护一个到目标服务器的 TCP 连接池，支持复用以降低延迟。
     * 
     * **核心机制**：
     * 1. **栈式缓存 (Stack-based Cache)**: 优先复用最近使用的连接 (LIFO)，提高缓存命中率。
     * 2. **僵尸检测 (Zombie Detection)**: 在复用前检查连接是否已由对端关闭，避免使用无效连接。
     * 3. **线程隔离**: 每个线程独享一个连接池，无锁设计，性能极致。
     * 
     * @note 必须确保 `io_context` 在 source 生命周期内保持运行。
     */
    class source
    {
        struct idle_item
        {
            tcp::socket *socket = nullptr;
            std::chrono::steady_clock::time_point last_used;
        }; // struct idle_item

    public:
        /**
         * @brief 构造连接池
         * @param ioc IO 上下文
         * @param resource 内存资源指针 (通常为线程局部池)
         * @param max_cache_per_endpoint 单个目标端点最大缓存连接数
         * @param max_idle_seconds 空闲连接最大存活时间（秒）
         * @note 推荐传入 `thread_local_pool` 以获得最佳性能。
         */
        explicit source(net::io_context &ioc,
                        const memory::resource_pointer resource = memory::current_resource(),
                        const std::uint32_t max_cache_per_endpoint = 32U,
                        const std::uint64_t max_idle_seconds = 60ULL)
            : ioc_(ioc),
              cache_(resource),
              max_cache_endpoint_(max_cache_per_endpoint),
              max_idle_time_(std::chrono::seconds(max_idle_seconds)) {}

        ~source()
        {
            clear();
        }

        // 禁止拷贝（每个线程独享一个池子）
        source(const source &) = delete;
        source &operator=(const source &) = delete;

        /**
         * @brief 获取一个 TCP 连接
         * @details 尝试获取一个到指定端点的连接。
         * 
         * **获取策略**：
         * 1. 查缓存：如果有空闲连接，且未超时、未断开，直接返回。
         * 2. 新建：如果缓存未命中，则发起异步 TCP 连接。
         * 
         * @param endpoint 目标端点
         * @return `unique_sock` 获取到的连接 (包装在 unique_ptr 中)
         * @note 该函数是异步的，会挂起当前协程直到连接建立或从缓存获取成功。
         * @warning 如果连接建立失败，将返回空的 `unique_sock`。
         */
        [[nodiscard]] auto acquire_tcp(tcp::endpoint endpoint) -> net::awaitable<unique_sock>;

        /**
         * @brief 归还连接（内部接口）
         * @param s socket 指针
         * @note 通常不需要手动调用，由 `unique_sock` 的析构器自动触发。
         */
        void recycle(tcp::socket *s);

        /**
         * @brief 归还连接（内部接口，带端点信息）
         * @param s socket 指针
         * @param endpoint 关联端点
         * @details 将连接放回对应端点的缓存栈中。
         * @note 如果该端点的缓存数量超过 `max_cache_endpoint_`，连接将被直接关闭并销毁。
         */
        void recycle(tcp::socket *s, const tcp::endpoint &endpoint);

    private:
        [[nodiscard]] static bool zombie_detection(const tcp::socket *s);

        void clear();

    private:
        net::io_context &ioc_;

        // 数据结构：hash_map + stack(模拟)
        // key: 目标 ip:port
        // value: 空闲连接列表
        memory::unordered_map<endpoint_key, memory::vector<idle_item>, endpoint_hash> cache_;

        // 单个目标最大缓存数 (防止内存爆炸)
        const std::uint32_t max_cache_endpoint_ = 32;

        // 空闲连接最大存活时间(超过则直接销毁，不检查)
        const std::chrono::seconds max_idle_time_{60};
    }; // class source

}
