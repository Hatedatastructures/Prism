/**
 * @file recursor.hpp
 * @brief 高性能 DNS 解析器门面
 * @details 整合自定义 DNS 客户端、缓存和规则引擎，
 * 替代系统 getaddrinfo 解析方式。提供完整的查询管道：
 * 规则匹配 → 缓存查找 → 请求合并 → 上游查询 → IP 过滤 → 缓存存储。
 *
 * 该组件设计为 per-worker 实例，不需要线程安全。
 * 复用现有的 coalescer 请求合并器避免重复查询。
 */

#pragma once

#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <forward-engine/resolve/coalescer.hpp>
#include <forward-engine/resolve/cache.hpp>
#include <forward-engine/resolve/config.hpp>
#include <forward-engine/resolve/resolver.hpp>
#include <forward-engine/resolve/rules.hpp>
#include <forward-engine/fault/code.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::resolve
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using udp = net::ip::udp;

    /**
     * @class recursor
     * @brief 高性能 DNS 解析器（自定义 DNS 客户端）。
     * @details 替代系统 getaddrinfo 解析，直接构造和解析 DNS 二进制报文。
     * 内部集成了请求合并、结果缓存和域名规则引擎。
     *
     * 查询管道流程：
     * @details 1. 域名规范化（转小写、去末尾点号）
     * @details 2. 规则匹配（address/cname/否定规则）
     * @details 3. 缓存查找（TTL 过期 + serve-stale）
     * @details 4. 请求合并（复用 coalescer）
     * @details 5. 上游查询（UDP/TCP/DoT/DoH）
     * @details 6. IP 过滤（黑名单 + bogus）
     * @details 7. TTL 钳制 + 缓存存储
     *
     * @note 该类不是线程安全的，应在单个 io_context 线程中使用。
     * @warning 上游服务器列表为空时，所有解析请求将失败。
     */
    class recursor
    {
    public:
        /**
         * @brief 构造 DNS 解析器。
         * @param ioc IO 上下文引用。
         * @param cfg DNS 解析器配置。
         * @param mr 内存资源指针。
         */
        explicit recursor(net::io_context &ioc, config cfg, memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 异步解析域名到 IP 地址列表。
         * @param host 主机名（自动规范化）。
         * @return pair<fault::code, vector<ip::address>>
         * @details 同时查询 A 和 AAAA 记录，返回合并的 IP 地址列表。
         */
        [[nodiscard]] auto resolve(std::string_view host)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>;

        /**
         * @brief 解析到 TCP 端点列表。
         * @param host 主机名。
         * @param port 服务端口字符串。
         * @return pair<fault::code, vector<tcp::endpoint>>
         */
        [[nodiscard]] auto resolve_tcp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>>;

        /**
         * @brief 解析到 UDP 端点。
         * @param host 主机名。
         * @param port 服务端口字符串。
         * @return pair<fault::code, udp::endpoint>
         */
        [[nodiscard]] auto resolve_udp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, udp::endpoint>>;

        // 查询是否禁用了 IPv6
        [[nodiscard]] auto ipv6_disabled() const noexcept -> bool { return config_.disable_ipv6; }

    private:
        /**
         * @brief 完整查询管道。
         * @param domain 已规范化的域名。
         * @param qt 查询类型。
         * @return pair<fault::code, vector<ip::address>>
         */
        [[nodiscard]] auto query_pipeline(std::string_view domain, qtype qt)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>;

        /**
         * @brief 检查 IP 是否在黑名单中。
         */
        [[nodiscard]] auto is_blacklisted(const net::ip::address &ip) const -> bool;

        /**
         * @brief 规范化域名：转小写，去掉末尾点号。
         */
        [[nodiscard]] static auto normalize(std::string_view domain, memory::resource_pointer mr) -> memory::string;

        net::io_context &ioc_;        // IO 上下文
        memory::resource_pointer mr_; // 内存资源
        config config_;          // DNS 配置
        resolver upstream_;      // 上游 DNS 客户端
        cache cache_;            // DNS 缓存
        rules_engine rules_;     // 域名规则引擎
        coalescer coalescer_;         // 请求合并器
    };

} // namespace ngx::resolve
