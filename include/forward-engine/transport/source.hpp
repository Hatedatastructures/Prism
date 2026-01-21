

#pragma once
#include <array>
#include <memory>
#include <chrono>
#include <cstddef>
#include <functional>
#include <boost/asio.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::transport
{

    namespace net = boost::asio;

    using tcp = boost::asio::ip::tcp;

    class source;

    /**
     * @brief 端点键
     * @details 用于唯一标识一个 TCP 端点 (IP 地址 + 端口号)
     * @note 支持 IPv4 和 IPv6。
     */
    struct endpoint_key
    {
        std::uint16_t port = 0;
        std::uint8_t family = 0; // 4 for IPv4, 6 for IPv6
        std::array<unsigned char, 16> address{}; // 16 bytes for IPv6

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
     */
    struct deleter
    {
        source *pool = nullptr;
        tcp::endpoint endpoint{};
        bool has_endpoint = false;
        void operator()(tcp::socket *ptr) const;
    }; // class deleter

    using exclusive_connection = std::unique_ptr<tcp::socket, deleter>;

    /**
     * @brief 连接缓存容器
     * @details 用于管理 TCP 连接的缓存，支持空闲连接的自动清理功能
     * @note 每个线程独享一个连接缓存容器，线程之间不共享。
     */
    class source
    {
        struct idle_item
        {
            tcp::socket *socket = nullptr;
            std::chrono::steady_clock::time_point last_used;
        }; // struct idle_item

    public:
        explicit source(net::io_context &ioc) : ioc_(ioc) {}

        ~source()
        {
            clear();
        }

        // 禁止拷贝（每个线程独享一个池子）
        source(const source &) = delete;
        source &operator=(const source &) = delete;

        [[nodiscard]] net::awaitable<exclusive_connection> acquire_tcp(tcp::endpoint endpoint);

        void recycle(tcp::socket *s);
        void recycle(tcp::socket *s, const tcp::endpoint &endpoint);

    private:
        [[nodiscard]] static bool zombie_detection(tcp::socket *s);

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
