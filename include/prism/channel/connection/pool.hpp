/**
 * @file pool.hpp
 * @brief TCP 连接池
 * @details 管理复用 TCP 连接，减少握手开销。提供配置
 * 结构体、RAII 连接包装器和运行统计。主类维护 LIFO
 * 栈式缓存，支持僵尸检测、线程隔离和后台定时清理。
 * @note 连接池设计为线程局部使用，不支持跨线程共享。
 * @warning 必须确保 io_context 在生命周期内保持运行。
 */
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

#include <boost/asio.hpp>

#include <prism/memory/container.hpp>
#include <prism/fault/code.hpp>

namespace psm::channel
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    class connection_pool;

    /**
     * @struct endpoint_key
     * @brief 端点键
     * @details 用于唯一标识一个 TCP 端点（IP + 端口），
     * 是连接池缓存的 Key。支持哈希和默认比较运算符。
     * @note 支持 IPv4 和 IPv6 两种协议族。
     * @warning address 字段必须根据 family 正确填充。
     */
    struct endpoint_key
    {
        std::uint16_t port = 0;                  // 端口号
        std::uint8_t family = 0;                 // 协议族：4 表示 IPv4，6 表示 IPv6
        std::array<unsigned char, 16> address{}; // IP 地址，IPv4 使用前 4 字节

        friend bool operator==(const endpoint_key &l, const endpoint_key &r) = default;
    };

    /**
     * @brief 从 TCP 端点构造端点键
     * @details 将 Boost.Asio 的 tcp::endpoint 转换为内部的 endpoint_key 结构，
     * 提取地址、端口和协议族信息。
     * @param endpoint TCP 端点
     * @return endpoint_key 端点键
     */
    endpoint_key make_endpoint_key(const tcp::endpoint &endpoint) noexcept;

    /**
     * @struct endpoint_hash
     * @brief 端点键哈希函数
     * @details 使用 FNV-1a 变体算法，一次性处理
     * port、family 和 address 所有字段。
     */
    struct endpoint_hash
    {
        /**
         * @brief 计算端点键的哈希值
         * @details 使用 FNV-1a 变体算法，一次性处理所有字段。
         * @param key 端点键
         * @return 哈希值
         */
        std::size_t operator()(const endpoint_key &key) const noexcept;
    };

    /**
     * @struct config
     * @brief 连接池配置
     * @details 控制连接池的行为参数，包括缓存容量、超时、
     * 缓冲区大小等。所有字段均有默认值。
     * @warning 设置过大的 max_cache_per_endpoint 可能导致
     * 内存压力。
     */
    struct config
    {
        std::uint32_t max_cache_per_endpoint = 32U; // 单个目标端点最大缓存连接数
        std::uint64_t connect_timeout_ms = 300ULL;  // 连接超时（毫秒）
        std::uint64_t max_idle_seconds = 30ULL;     // 空闲连接最大存活时间（秒）
        std::uint64_t cleanup_interval_sec = 10ULL; // 后台清理间隔（秒）
        std::uint32_t recv_buffer_size = 65536U;    // 接收缓冲区大小（字节）
        std::uint32_t send_buffer_size = 65536U;    // 发送缓冲区大小（字节）
        bool tcp_nodelay = true;                    // 是否启用 TCP_NODELAY
        bool keep_alive = true;                     // 是否启用 SO_KEEPALIVE
        bool cache_ipv6 = false;                    // 是否缓存 IPv6 连接
    }; // struct config

    /**
     * @class pooled_connection
     * @brief 连接池连接的 RAII 包装器
     * @details 内联存储 pool 指针、socket 指针和 endpoint，
     * 零堆分配。析构时自动归还连接到连接池。
     * @note 归还逻辑由 connection_pool::recycle() 执行，
     * 包括健康检测和容量检查。
     * @warning 移动后源对象变为无效状态，不应再被使用。
     */
    class pooled_connection
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造一个无效的空连接包装器，所有指针为空。
         */
        pooled_connection() = default;

        /**
         * @brief 构造函数
         * @details 使用连接池指针、socket 指针和目标端点构造连接包装器。
         * @param pool 关联的连接池指针，归还时使用
         * @param socket 持有的 socket 指针
         * @param endpoint 关联的目标端点
         */
        pooled_connection(connection_pool *pool, tcp::socket *socket, tcp::endpoint endpoint)
            : pool_(pool), socket_(socket), endpoint_(std::move(endpoint))
        {
        }

        /**
         * @brief 析构函数
         * @details 析构时自动调用 reset() 归还或关闭连接。
         */
        ~pooled_connection();

        pooled_connection(const pooled_connection &) = delete;
        pooled_connection &operator=(const pooled_connection &) = delete;

        /**
         * @brief 移动构造函数
         * @details 转移连接的所有权，移动后源对象变为无效状态。
         * @param other 要移动的连接包装器
         */
        pooled_connection(pooled_connection &&other) noexcept
            : pool_(other.pool_), socket_(other.socket_), endpoint_(other.endpoint_)
        {
            other.pool_ = nullptr;
            other.socket_ = nullptr;
        }

        /**
         * @brief 移动赋值运算符
         * @details 转移连接的所有权，移动后源对象变为无效状态。
         * @param other 要移动的连接包装器
         * @return pooled_connection& 当前对象的引用
         */
        pooled_connection &operator=(pooled_connection &&other) noexcept;

        /**
         * @brief 获取 socket 指针
         * @details 返回持有的 socket 指针，无效时返回 nullptr。
         * @return tcp::socket* socket 指针
         */
        [[nodiscard]] tcp::socket *get() const noexcept { return socket_; }

        /**
         * @brief 解引用 socket
         * @details 返回 socket 的引用，调用前必须确保 valid() 为 true。
         * @return tcp::socket& socket 引用
         */
        [[nodiscard]] tcp::socket &operator*() const noexcept { return *socket_; }

        /**
         * @brief 访问 socket 成员
         * @details 返回 socket 指针，用于通过箭头操作符访问成员。
         * @return tcp::socket* socket 指针
         */
        [[nodiscard]] tcp::socket *operator->() const noexcept { return socket_; }

        /**
         * @brief 检查连接是否有效
         * @details 检查 socket 指针是否非空。
         * @return bool 有效返回 true
         */
        [[nodiscard]] bool valid() const noexcept { return socket_ != nullptr; }

        /**
         * @brief 检查连接是否有效
         * @details 隐式转换为 bool，等同于 valid()。
         * @return bool 有效返回 true
         */
        [[nodiscard]] explicit operator bool() const noexcept { return valid(); }

        /**
         * @brief 释放连接所有权，不归还到连接池
         * @details 放弃连接的所有权，调用方接管 socket 指针并负责关闭。
         * 调用后 valid() 返回 false。
         * @return socket 指针，调用方负责关闭
         * @warning 调用方必须确保最终关闭返回的 socket，否则会泄漏连接。
         */
        [[nodiscard]] tcp::socket *release() noexcept;

        /**
         * @brief 归还或关闭连接
         * @details 如果持有有效连接且有关联的连接池，归还到连接池进行
         * 健康检测和可能的复用；否则直接关闭并释放 socket。
         */
        void reset();

    private:
        connection_pool *pool_ = nullptr; // 关联的连接池指针，归还时使用
        tcp::socket *socket_ = nullptr;   // 持有的 socket 指针
        tcp::endpoint endpoint_{};        // 关联的目标端点，归还时用于缓存定位
    };

    /**
     * @struct pool_stats
     * @brief 连接池统计信息
     * @details 记录运行时指标，用于监控和诊断。
     * idle_count 和 endpoint_count 为实时计算值。
     * @note 通过 connection_pool::stats() 获取快照。
     */
    struct pool_stats
    {
        std::size_t idle_count = 0;      // 当前空闲连接数
        std::size_t endpoint_count = 0;  // 有缓存的端点数
        std::size_t total_acquires = 0;  // 总获取次数
        std::size_t total_hits = 0;      // 缓存命中次数
        std::size_t total_creates = 0;   // 新建连接次数
        std::size_t total_recycles = 0;  // 归还次数
        std::size_t total_evictions = 0; // 驱逐次数（容量满/不健康/过期）
    };

    /**
     * @class connection_pool
     * @brief TCP 连接池
     * @details 维护到目标服务器的 TCP 连接池，支持复用。
     * 核心机制包括 LIFO 栈式缓存、僵尸检测、线程隔离
     * 和后台定时清理。
     * @note 连接池设计为线程局部使用，不支持跨线程共享。
     * @warning 必须确保 io_context 在生命周期内保持运行。
     */
    class connection_pool
    {
        // 空闲连接项，包含 socket 指针和最后使用时间
        struct idle_item
        {
            tcp::socket *socket = nullptr;                   // socket 指针
            std::chrono::steady_clock::time_point last_used; // 最后使用时间
        };

    public:
        /**
         * @brief 构造连接池
         * @details 使用 IO 上下文和可选的内存资源、配置参数初始化连接池。
         * 内存资源用于分配内部缓存容器。
         * @param ioc IO 上下文，用于异步操作和定时器
         * @param resource 内存资源指针（通常为线程局部池）
         * @param config 连接池配置，默认为 config{}
         */
        explicit connection_pool(net::io_context &ioc, const memory::resource_pointer resource = memory::current_resource(),
                                 const config &config = {})
            : ioc_(ioc), cache_(resource), config_(config) {}

        /**
         * @brief 析构函数
         * @details 调用 clear() 关闭并释放所有缓存连接。
         */
        ~connection_pool()
        {
            clear();
        }

        connection_pool(const connection_pool &) = delete;
        connection_pool &operator=(const connection_pool &) = delete;

        /**
         * @brief 获取一个 TCP 连接
         * @details 优先从缓存中复用 LIFO 栈顶连接，依次进行过期检查和
         * 健康检测；缓存未命中时通过 co_spawn + timer 方案创建新连接，
         * 超时由 config::connect_timeout_ms 控制。新建连接成功后
         * 自动设置 TCP_NODELAY、SO_KEEPALIVE 等选项。
         * @param endpoint 目标 TCP 端点
         * @return pair<fault::code, pooled_connection> 错误码和连接包装器，
         * 成功时 code 为 success 且连接有效
         * @note 超时返回 fault::code::timeout，连接失败返回 fault::code::bad_gateway。
         * @warning 连接包装器必须在 socket 不再需要前析构或显式 reset/release，
         * 否则连接不会被归还到池中。
         */
        [[nodiscard]] auto async_acquire(tcp::endpoint endpoint)
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;

        /**
         * @brief 归还连接（内部接口，由 pooled_connection 调用）
         * @details 对归还的连接执行 IPv6 过滤、健康检测和容量检查，
         * 满足条件的连接入栈等待复用，不满足条件的连接被直接关闭。
         * @param s 待归还的 socket 指针
         * @param endpoint 关联的目标端点
         */
        void recycle(tcp::socket *s, const tcp::endpoint &endpoint);

        /**
         * @brief 启动后台清理协程
         * @details 投递一个协程到 io_context，按 config::cleanup_interval_sec
         * 指定的间隔周期性调用 cleanup() 移除过期连接。重复调用无效。
         * @note 必须在 io_context 运行前调用，否则清理协程不会启动。
         */
        void start();

        /**
         * @brief 获取连接池统计快照
         * @details 返回统计信息的快照，其中 idle_count 和 endpoint_count
         * 为实时计算值，其余为累计计数器。计数器使用 memory_order_relaxed
         * 顺序，不保证与其他操作的原子性。
         * @return pool_stats 统计信息快照
         */
        [[nodiscard]] auto stats() const -> pool_stats;

        /**
         * @brief 获取连接池配置（只读）
         * @details 返回当前连接池的配置参数。
         * @return const config& 连接池配置的常量引用
         */
        [[nodiscard]] const config &config() const noexcept { return config_; }

    private:
        /**
         * @brief 清理所有缓存连接
         * @details 取消后台清理定时器，关闭并释放所有缓存中的 socket，
         * 清空缓存容器。在析构函数中调用。
         */
        void clear();

        /**
         * @brief 后台清理：移除过期连接
         * @details 遍历缓存中所有端点的连接栈，移除超过 max_idle_seconds
         * 的过期连接。使用原地压缩算法，避免不必要的内存分配。
         * 空栈的端点条目会被一并移除。
         */
        void cleanup();

        net::io_context &ioc_;                                                                // IO 上下文，用于异步操作和定时器
        memory::unordered_map<endpoint_key, memory::vector<idle_item>, endpoint_hash> cache_; // 连接缓存，按端点键组织，每个端点使用 LIFO 栈
        struct config config_;                                                                // 连接池配置
        std::optional<net::steady_timer> cleanup_timer_;                                      // 后台清理定时器，start() 后有效
        std::shared_ptr<std::atomic<bool>> shutdown_flag_;                                    // 退出标志，clear() 设置后协程安全退出

        bool started_{false}; // start() 是否已调用

        mutable std::size_t stat_acquires_{0};  // 总获取次数
        mutable std::size_t stat_hits_{0};      // 缓存命中次数
        mutable std::size_t stat_creates_{0};   // 新建连接次数
        mutable std::size_t stat_recycles_{0};  // 归还次数
        mutable std::size_t stat_evictions_{0}; // 驱逐次数（容量满/不健康/过期）
        mutable std::size_t stat_idle_{0};      // 当前空闲连接数
        mutable std::size_t stat_endpoints_{0}; // 有缓存的端点数
    };
}
