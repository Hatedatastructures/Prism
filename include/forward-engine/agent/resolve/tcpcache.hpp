/**
 * @file tcpcache.hpp
 * @brief TCP 解析缓存
 * @details 该组件为 TCP 可靠传输提供完整的解析解决方案，集成了
 * DNS 解析、请求合并、端点缓存和连接池获取等功能。通过缓存
 * 已解析的端点信息，避免重复的 DNS 查询开销；通过请求合并机制，
 * 将同一目标的并发请求合并为单次 DNS 解析，有效降低系统负载。
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <forward-engine/agent/resolve/coalescer.hpp>
#include <forward-engine/agent/resolve/transparent.hpp>
#include <forward-engine/fault/code.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/channel/pool/pool.hpp>

namespace ngx::agent::resolve
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using tcpool = ngx::channel::tcpool;
    using unique_sock = ngx::channel::unique_sock;

    /**
     * @class tcpcache
     * @brief TCP 解析缓存。
     * @details 负责解析主机名到 TCP 端点并建立连接，同时缓存
     * 解析结果以提升性能。实现两级优化策略：首先检查本地缓存，
     * 若命中且未过期则尝试连接缓存的端点列表；若未命中，
     * 则检查是否有相同目标的解析请求正在进行中，若有则等待其
     * 完成后复用结果；否则发起新的 DNS 解析并将结果存入缓存。
     * 缓存采用 FIFO 淘汰策略，当记录数超过上限时移除最旧的条目。
     * @note 该类不是线程安全的，应在单个 strand 上下文中使用。
     * @warning 缓存的端点信息可能因目标服务器地址变更而失效，
     * 调用方应合理设置 TTL 参数。
     * @throws 不抛出任何异常，所有错误通过返回码表达。
     */
    class tcpcache final
    {
    public:
        using result = std::pair<fault::code, unique_sock>;

        /**
         * @brief 构造可靠传输解析器。
         * @param pool 共享传输源，用于获取 TCP 连接。
         * @param executor 执行器，用于解析器和请求合并定时器。
         * @param mr 内存资源，用于缓存存储分配。
         * @param ttl 缓存记录的生存时间，默认 30 秒。
         * @param max_entries 缓存最大记录数，默认 10000 条。
         */
        explicit tcpcache(tcpool &pool, const net::any_io_executor &executor, memory::resource_pointer mr = memory::current_resource(),
                                   std::chrono::seconds ttl = std::chrono::seconds(120), std::size_t max_entries = 10000);

        /**
         * @brief 解析目标主机并建立连接。
         * @param host 主机名。
         * @param port 服务端口。
         * @return 协程对象，返回状态码与 TCP 套接字的配对。
         * @details 该方法是解析器的核心入口，实现了完整的解析流程。
         * 首先检查缓存是否存在有效记录，若存在则尝试连接缓存的
         * 端点列表。若缓存未命中或连接失败，则检查是否有正在
         * 进行的相同请求，若有则等待其完成后复用结果。否则
         * 发起新的 DNS 解析，将结果存入缓存并尝试连接。
         */
        [[nodiscard]] auto resolve(std::string_view host, std::string_view port) -> net::awaitable<result>;

    private:
        /**
         * @struct record
         * @brief 缓存记录结构体。
         * @details 存储已解析的端点列表和过期时间。
         */
        struct record
        {
            memory::vector<tcp::endpoint> endpoints;      // 解析结果端点列表
            std::chrono::steady_clock::time_point expire; // 过期时间
            std::chrono::steady_clock::time_point inserted; // 插入时间（用于 FIFO 淘汰）
        };

        using hash_map = memory::unordered_map<memory::string, record, transparent_hash, transparent_equal>;

        /**
         * @brief 从缓存获取端点并尝试连接。
         * @param lookup 查找键。
         * @param now 当前时间点。
         * @return 协程对象，返回成功连接的套接字或空指针。
         * @details 检查缓存中是否存在有效记录，若存在则依次尝试
         * 连接记录中的端点。连接成功则返回套接字，否则继续尝试
         * 下一个端点。若所有端点均失败，清除该缓存记录。
         */
        [[nodiscard]] auto async_connect(const lookup_key &lookup, std::chrono::steady_clock::time_point now)
            -> net::awaitable<unique_sock>;

        tcpool &pool_;              // 共享传输源
        tcp::resolver resolver_;      // TCP DNS 解析器
        memory::resource_pointer mr_; // 内存资源
        std::chrono::seconds ttl_;    // 缓存生存时间
        std::size_t max_entries_;     // 最大缓存条目数
        hash_map records_;            // 端点缓存表
        coalescer coalescer_;         // 请求合并器
    };
} // namespace ngx::agent::resolve
