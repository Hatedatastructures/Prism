/**
 * @file cache.hpp
 * @brief DNS 结果缓存
 * @details 提供 DNS 解析结果的内存缓存，支持正向缓存（IP 地址列表）和
 * 负缓存（解析失败标记）。缓存键采用 "domain:qtype_number" 格式，
 * 复用现有的 transparent_hash / transparent_equal 实现异构查找，
 * 避免构造临时键对象的额外开销。
 *
 * 缓存策略：
 * @details - TTL 过期：条目在过期后可配置为 serve-stale 模式，返回旧数据
 *   同时允许调用方触发后台刷新。
 * @details - FIFO 淘汰：当缓存条目数超过上限时，按插入时间淘汰最旧的条目。
 * @details - 负缓存：解析失败的记录会以较短的 TTL 缓存，防止对不可达域名
 *   的重复解析请求造成上游压力。
 *
 * @note 该类不是线程安全的，应在单个 strand 上下文中使用。
 * @warning 过期数据仅在 serve_stale 模式下返回，调用方应据此决定是否刷新。
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string_view>

#include <boost/asio.hpp>

#include <prism/resolve/packet.hpp>
#include <prism/resolve/transparent.hpp>
#include <prism/memory/container.hpp>

namespace psm::resolve
{
    namespace net = boost::asio;

    // qtype 由 message.hpp 提供

    /**
     * @struct cache_entry
     * @brief DNS 缓存条目
     * @details 存储单次 DNS 解析的结果及其元数据，包括解析得到的 IP 地址列表、
     * 原始 TTL、过期时间、插入时间和负缓存标记。
     */
    struct cache_entry
    {
        memory::vector<net::ip::address> ips;           // 解析结果 IP 地址列表
        uint32_t ttl{0};                                // 原始 TTL（秒）
        std::chrono::steady_clock::time_point expire;   // 过期时间
        std::chrono::steady_clock::time_point inserted; // 插入时间（用于 FIFO 淘汰）
        bool failed{false};                             // 负缓存标记

        explicit cache_entry(memory::resource_pointer mr = memory::current_resource())
            : ips(mr)
        {
        }
    };

    /**
     * @class cache
     * @brief DNS 结果缓存容器
     * @details 负责存储和检索 DNS 解析结果，支持正向缓存和负缓存。
     * 缓存键格式为 "domain:qtype_number"（如 "www.example.com:1"），
     * 通过 transparent_hash 的 string_view 重载实现零分配查找。
     *
     * 使用方式：
     * @details 1. 调用 get() 查询缓存，判断是否命中；
     * @details 2. 缓存未命中时发起 DNS 查询；
     * @details 3. 查询成功调用 put() 写入正向缓存；
     * @details 4. 查询失败调用 put_negative() 写入负缓存。
     *
     * @note 该类不是线程安全的，应在单个 strand 上下文中使用。
     * @warning serve_stale 模式下返回的数据可能已过期，调用方应异步刷新。
     */
    class cache
    {
    public:
        /**
         * @brief 构造 DNS 缓存
         * @param mr 内存资源指针，为 null 时使用 current_resource()
         * @param ttl 默认缓存 TTL（秒），用于 put() 未指定 TTL 时的回退值
         * @param max_entries 缓存最大条目数，超过后触发 FIFO 淘汰
         * @param serve_stale 是否在过期后返回旧数据（serve-stale 模式）
         */
        explicit cache(memory::resource_pointer mr = memory::current_resource(),
                       std::chrono::seconds ttl = std::chrono::seconds(120), std::size_t max_entries = 10000,
                       bool serve_stale = true);

        /**
         * @brief 查找缓存
         * @param domain 域名
         * @param qt 查询类型
         * @return nullopt 表示未命中；返回空 vector 表示负缓存命中；返回非空 vector 表示正向缓存命中
         *
         * @details 查找逻辑：
         * - 未命中：返回 nullopt
         * - 未过期：返回 ips（若 failed 为 true 则返回空 vector）
         * - 已过期 + serve_stale：返回旧数据（调用方应据此触发后台刷新）
         * - 已过期 + !serve_stale：删除条目并返回 nullopt
         */
        [[nodiscard]] auto get(std::string_view domain, qtype qt) -> std::optional<memory::vector<net::ip::address>>;

        /**
         * @brief 写入正向缓存
         * @param domain 域名
         * @param qt 查询类型
         * @param ips 解析得到的 IP 地址列表
         * @param ttl_seconds 缓存 TTL（秒）
         *
         * @details 创建新的缓存条目并插入到缓存表中。如果当前条目数
         * 超过 max_entries_，则按 FIFO 策略淘汰最旧的条目。
         */
        void put(std::string_view domain, qtype qt, const memory::vector<net::ip::address> &ips,
                 uint32_t ttl_seconds);

        /**
         * @brief 写入负缓存
         * @param domain 域名
         * @param qt 查询类型
         * @param negative_ttl 负缓存 TTL（秒），默认 30 秒
         *
         * @details 记录解析失败的域名，在 negative_ttl 期间直接返回
         * 空结果，避免对不可达域名的重复查询造成上游压力。
         */
        void put_negative(std::string_view domain, qtype qt,
                          std::chrono::seconds negative_ttl = std::chrono::seconds(30));

        /**
         * @brief 清理过期条目
         * @details 遍历缓存表，删除所有已过期的条目。
         * 在 serve_stale 模式下也会清理过期条目。
         */
        void evict_expired();

    private:
        /**
         * @brief 构造缓存键
         * @param domain 域名
         * @param qt 查询类型
         * @return 格式为 "domain:qtype_number" 的 PMR 字符串
         *
         * @details 将域名和查询类型数值拼接为缓存键，如 "www.example.com:1"
         * (A 记录) 或 "www.example.com:28" (AAAA 记录)。
         */
        [[nodiscard]] auto make_key(std::string_view domain, qtype qt) const -> memory::string;

        memory::resource_pointer mr_;      // 内存资源
        std::chrono::seconds default_ttl_; // 默认 TTL
        std::size_t max_entries_;          // 最大条目数
        bool serve_stale_;                 // serve-stale 模式开关

        // 复用现有的 transparent_hash / transparent_equal
        using cache_map = memory::unordered_map<memory::string, cache_entry,transparent_hash,transparent_equal>;
        cache_map entries_; // 缓存表
    };

} // namespace psm::resolve
