/**
 * @file source.hpp
 * @brief TCP 连接池
 * @details 管理复用 TCP 连接，减少握手开销。
 *
 * 架构说明：
 * - 连接池容器：`source` 类维护 TCP 连接池，支持连接复用；
 * - 端点键：`endpoint_key` 结构用于唯一标识 TCP 端点；
 * - 哈希函数：`endpoint_hash` 结构用于支持哈希表查找；
 * - 智能指针：`unique_sock` 类型使用自定义删除器管理连接生命周期。
 *
 * 设计特性：
 * - 栈式缓存：优先复用最近使用的连接（LIFO），提高缓存命中率；
 * - 僵尸检测：在复用前检查连接是否已由对端关闭，避免使用无效连接；
 * - 线程隔离：每个线程独享一个连接池，无锁设计，性能极致；
 * - 自定义删除器：`unique_sock` 离开作用域时，自动归还连接到连接池。
 *
 * @note 连接池设计为线程局部使用，不支持跨线程共享。
 * @warning 必须确保 `io_context` 在 `source` 生命周期内保持运行。
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
 * @warning - 该命名空间的内容主要用于底层网络 IO，请勿在业务逻辑中直接调用。
 * @warning - 连接池设计为线程局部使用，不支持跨线程共享。
 * @throws 传输层操作可能抛出 `std::bad_alloc`（内存不足）或 `std::runtime_error`（网络错误）
 * @details 负责底层的数据搬运、连接管理和协议封装。
 * 该命名空间实现了基于 Boost.Asio 的现代 C++ 异步网络 IO，包含：
 * @details - 传输抽象：`transmission` 接口和 `reliable`、`unreliable` 实现；
 * @details - 连接池：`source` 类管理到上游服务的连接复用；
 * @details - IO 适配：`connector` 模板适配自定义接口到 Boost.Asio 概念；
 * @details - 反向代理：`reverse` 类实现反向代理的 TCP 隧道。
 *
 *
 * 传输层层次：
 *
 * ```
 * Boost.Asio Socket (tcp::socket, udp::socket)
 * └── ngx::transport::transmission (抽象接口)
 *     ├── ngx::transport::reliable (TCP 实现)
 *     └── ngx::transport::unreliable (UDP 实现)
 *         └── ngx::transport::connector (适配器)
 *             └── Boost.Beast / Boost.Asio.SSL
 * ```
 */
namespace ngx::transport
{

    namespace net = boost::asio;

    using tcp = boost::asio::ip::tcp;

    class source;

    /**
     * @struct endpoint_key
     * @brief 端点键
     * @details 用于唯一标识一个 TCP 端点（IP 地址 + 端口号）。
     * 它是连接池缓存 (`unordered_map`) 的 Key。
     *
     * 核心职责：
     * @details - 唯一标识：通过 `address`、`family` 和 `port` 组合唯一标识端点；
     * @details - 哈希支持：支持 `endpoint_hash` 哈希函数，用于哈希表查找；
     * @details - 比较支持：支持默认比较运算符，用于哈希表键比较。
     *
     * 字段说明：
     * @details - `port`：端口号（16 位无符号整数）；
     * @details - `family`：协议族（4 表示 IPv4，6 表示 IPv6）；
     * @details - `address`：地址数据（IPv6 使用全部 16 字节，IPv4 使用前 4 字节）。
     *
     * @note 支持 IPv4 和 IPv6 两种协议族。
     * @warning `address` 字段必须根据 `family` 字段正确填充。
     */
    struct endpoint_key
    {
        std::uint16_t port = 0;                          // 端口号
        std::uint8_t family = 0;                           // 协议族 (4 for IPv4, 6 for IPv6)
        std::array<unsigned char, 16> address{};            // 地址数据 (IPv6 使用全部 16 字节，IPv4 使用前 4 字节)

        friend bool operator==(const endpoint_key &l, const endpoint_key &r) = default;
    };

    /**
     * @brief 创建端点键
     * @details 从 `tcp::endpoint` 对象创建 `endpoint_key` 结构。该函数将端点信息
     * 提取并编码为 `endpoint_key` 格式，用于连接池的哈希表键。
     *
     * 编码流程：
     * @details - 端点提取：从 `tcp::endpoint` 提取 IP 地址和端口号；
     * @details - 协议族判断：根据 IP 地址类型设置 `family` 字段；
     * @details - 地址编码：将 IP 地址编码为 `address` 数组格式；
     * @details - 端口设置：将端口号设置到 `port` 字段。
     *
     * @param endpoint TCP 端点对象
     * @return `endpoint_key` 端点键结构
     * @note 该函数不抛出异常。
     * @warning 端点对象必须有效，否则结果未定义。
     */
    inline endpoint_key make_endpoint_key(const tcp::endpoint &endpoint) noexcept;

    /**
     * @struct endpoint_hash
     * @brief 端点键哈希函数
     * @details 用于将 `endpoint_key` 类型的对象映射到哈希值，支持 `std::unordered_map` 等容器。
     * 该结构实现了标准哈希函数接口，可用于 STL 容器。
     *
     * 核心职责：
     * @details - 哈希计算：将 `endpoint_key` 的字段组合为哈希值；
     * @details - 低冲突率：通过组合多个字段降低哈希冲突概率；
     * @details - 标准接口：实现 `operator()` 运算符，符合标准哈希函数接口。
     *
     * 哈希算法：
     * @details - 字段组合：将 `address`、`family` 和 `port` 字段组合；
     * @details - 位运算：使用异或和位移操作混合字段；
     * @details - 模运算：对哈希表大小取模，确定存储位置。
     *
     * @note 该哈希函数是确定性的，相同的键总是产生相同的哈希值。
     * @warning 哈希函数可能产生冲突，容器需要处理冲突情况。
     */
    struct endpoint_hash
    {
        /**
         * @brief 哈希运算符
         * @details 将 `endpoint_key` 对象映射到哈希值。
         * @param key 端点键对象
         * @return `std::size_t` 哈希值
         * @note 该函数不抛出异常。
         */
        std::size_t operator()(const endpoint_key &key) const noexcept;
    };

    /**
     * @struct deleter
     * @brief 连接缓存删除器
     * @details 自定义删除器，用于将 socket 归还到连接池而不是直接析构。
     * 当 `unique_sock` 离开作用域时，该删除器会被调用。
     *
     * 核心职责：
     * @details - 连接归还：将 socket 归还到连接池而不是直接关闭；
     * @details - 端点关联：维护 socket 与端点的关联，用于正确归还；
     * @details - 生命周期管理：在智能指针析构时自动调用，确保资源正确释放。
     *
     * 归还逻辑：
     * @details - 端点检查：检查是否有关联的端点信息；
     * @details - 连接归还：如果有端点信息，调用 `source::recycle` 归还连接；
     * @details - 直接关闭：如果没有端点信息，直接关闭 socket。
     *
     * @note 当 `unique_sock` 离开作用域时，该删除器会被调用。
     * @warning 删除器不应手动调用，应通过智能指针生命周期自动触发。
     */
    struct deleter
    {
        source *pool = nullptr;   // 连接池指针
        tcp::endpoint endpoint{};   // 对应的端点
        bool has_endpoint = false; // 是否有关联端点

        /**
         * @brief 删除运算符
         * @details 将 socket 归还到连接池或直接关闭。
         * @param ptr socket 指针
         * @note 该运算符由智能指针在析构时自动调用。
         * @warning 手动调用该运算符可能导致重复释放。
         */
        void operator()(tcp::socket *ptr) const;
    }; // class deleter

    /**
     * @brief 独占式 TCP 连接智能指针
     * @details 用于管理 TCP 连接的生命周期，确保在不再需要时及时关闭连接。
     * 每个连接只能被一个 `unique_sock` 实例持有，防止并发访问问题。
     *
     * 核心职责：
     * @details - 所有权管理：独占 TCP 连接的所有权；
     * @details - 自动归还：析构时自动调用自定义删除器归还连接；
     * @details - 线程安全：每个连接只能被一个智能指针持有，避免竞争。
     *
     * 使用场景：
     * @details - 连接获取：从连接池获取连接时，包装为 `unique_sock`；
     * @details - 作用域管理：使用 RAII 模式，确保连接在离开作用域时归还；
     * @details - 异常安全：即使在异常情况下，连接也会被正确归还。
     *
     * @note 每个连接只能被一个 `unique_sock` 实例持有，防止并发访问问题。
     * @warning 不应拷贝或移动 `unique_sock` 到另一个智能指针，否则可能导致重复释放。
     */
    using unique_sock = std::unique_ptr<tcp::socket, deleter>;

    /**
     * @class source
     * @brief 连接缓存容器 (Connection Pool)
     * @details 维护一个到目标服务器的 TCP 连接池，支持复用以降低延迟。
     * 该类是传输层的核心组件，用于管理 TCP 连接的生命周期和复用。
     *
     * 核心机制：
     * @details - 栈式缓存：优先复用最近使用的连接（LIFO），提高缓存命中率；
     * @details - 僵尸检测：在复用前检查连接是否已由对端关闭，避免使用无效连接；
     * @details - 线程隔离：每个线程独享一个连接池，无锁设计，性能极致。
     *
     * 核心职责：
     * @details - 连接获取：`acquire_tcp` 方法获取连接，优先从缓存获取；
     * @details - 连接归还：`recycle` 方法归还连接到缓存；
     * @details - 缓存清理：`clear` 方法清理所有缓存连接；
     * @details - 僵尸检测：`zombie_detection` 方法检测无效连接。
     *
     * 线程安全性设计：
     * @details - 线程局部：每个线程独享一个连接池实例；
     * @details - 无锁设计：所有操作都在单线程内完成，无需锁同步；
     * @details - 移动禁止：禁止拷贝和移动，确保连接池不被跨线程转移。
     *
     * @note 必须确保 `io_context` 在 `source` 生命周期内保持运行。
     * @warning 连接池设计为线程局部使用，不支持跨线程共享。
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
         * @details 创建 TCP 连接池实例，配置缓存参数和资源管理器。
         * 该构造函数初始化连接池的所有内部数据结构。
         *
         * 构造流程：
         * @details - IO 上下文：接收 `io_context` 引用，用于异步操作；
         * @details - 内存资源：接收内存资源指针，用于分配内部数据结构；
         * @details - 缓存配置：设置单个端点的最大缓存连接数；
         * @details - 超时配置：设置空闲连接的最大存活时间。
         *
         * @param ioc IO 上下文，用于异步操作
         * @param resource 内存资源指针（通常为线程局部池）
         * @param max_cache_per_endpoint 单个目标端点最大缓存连接数
         * @param max_idle_seconds 空闲连接最大存活时间（秒）
         * @note 推荐传入 `thread_local_pool` 以获得最佳性能。
         * @warning `max_cache_per_endpoint` 过大可能导致内存占用过高。
         * @throws `std::bad_alloc` 如果内存分配失败
         */
        explicit source(net::io_context &ioc,
                        const memory::resource_pointer resource = memory::current_resource(),
                        const std::uint32_t max_cache_per_endpoint = 32U,
                        const std::uint64_t max_idle_seconds = 60ULL)
            : ioc_(ioc),
              cache_(resource),
              max_cache_endpoint_(max_cache_per_endpoint),
              max_idle_time_(std::chrono::seconds(max_idle_seconds)) {}

        /**
         * @brief 析构函数
         * @details 析构连接池，清理所有缓存连接。该析构函数确保所有资源被正确释放。
         * @note 析构函数会调用 `clear` 方法清理所有缓存连接。
         */
        ~source()
        {
            clear();
        }

        // 禁止拷贝（每个线程独享一个池子）
        source(const source &) = delete;
        source &operator=(const source &) = delete;

        /**
         * @brief 获取一个 TCP 连接
         * @details 尝试获取一个到指定端点的连接。优先从缓存获取，如果缓存未命中，
         * 则发起异步 TCP 连接。
         *
         * 获取策略：
         * @details - 查缓存：如果有空闲连接，且未超时、未断开，直接返回；
         * @details - 新建：如果缓存未命中，则发起异步 TCP 连接。
         *
         * @param endpoint 目标端点
         * @return `unique_sock` 获取到的连接（包装在 unique_ptr 中）
         * @note 该函数是异步的，会挂起当前协程直到连接建立或从缓存获取成功。
         * @warning 如果连接建立失败，将返回空的 `unique_sock`。
         * @throws `std::bad_alloc` 如果内存分配失败
         */
        [[nodiscard]] auto acquire_tcp(tcp::endpoint endpoint) -> net::awaitable<unique_sock>;

        /**
         * @brief 归还连接（内部接口）
         * @details 将 socket 归还到连接池。该方法是内部接口，通常由 `unique_sock` 的析构器自动触发。
         * @param s socket 指针
         * @note 通常不需要手动调用，由 `unique_sock` 的析构器自动触发。
         * @warning 手动调用该函数可能导致连接被重复归还。
         */
        void recycle(tcp::socket *s);

        /**
         * @brief 归还连接（内部接口，带端点信息）
         * @details 将 socket 归还到对应端点的缓存中。该方法是内部接口，通常由 `unique_sock` 的析构器自动触发。
         *
         * 归还逻辑：
         * @details - 端点查找：查找端点对应的缓存列表；
         * @details - 僵尸检测：检查连接是否有效，无效则关闭；
         * @details - 缓存检查：检查该端点的缓存数量是否超过限制；
         * @details - 归还或关闭：如果未超限则归还，否则关闭连接。
         *
         * @param s socket 指针
         * @param endpoint 关联端点
         * @note 如果该端点的缓存数量超过 `max_cache_endpoint_`，连接将被直接关闭并销毁。
         * @warning 手动调用该函数可能导致连接被重复归还。
         */
        void recycle(tcp::socket *s, const tcp::endpoint &endpoint);

    private:
        /**
         * @brief 僵尸连接检测
         * @details 检查 TCP 连接是否已由对端关闭。该方法通过检查 socket 状态
         * 判断连接是否仍然有效。
         *
         * 检测逻辑：
         * @details - Socket 检查：检查 socket 是否仍然打开；
         * @details - 错误检查：检查是否有挂起的错误；
         * @details - 返回结果：返回 `true` 表示连接有效，`false` 表示连接已关闭。
         *
         * @param s socket 指针
         * @return `bool` 连接是否有效（`true` 表示有效，`false` 表示已关闭）
         * @note 该函数不抛出异常。
         * @warning 检测结果可能不准确，建议结合其他方法综合判断。
         */
        [[nodiscard]] static bool zombie_detection(const tcp::socket *s);

        /**
         * @brief 清理所有缓存连接
         * @details 清理连接池中的所有缓存连接。该方法在析构函数中调用，确保所有资源被正确释放。
         * @note 该函数不抛出异常。
         * @warning 清理后连接池中的所有连接都将被关闭。
         */
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
