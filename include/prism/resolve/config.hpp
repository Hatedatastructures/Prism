/**
 * @file config.hpp
 * @brief DNS 解析器配置
 * @details 定义 DNS 解析器的全部配置类型，包括上游服务器、解析模式、
 * 域名规则和 IP 过滤等。所有容器类型均使用 PMR 多态内存资源分配器，
 * 支持运行时切换内存资源，与自定义内存池无缝集成。该文件为 header-only 实现。
 *
 * 核心组件包括四个部分。第一部分是上游服务器配置，包含协议类型、地址解析
 * 和连接参数，定义了 dns_protocol 枚举和 dns_remote 结构体。
 * 第二部分是解析策略，定义了 resolve_mode 枚举，支持最快响应、首次响应
 * 和回退三种模式。第三部分是域名规则，支持地址映射和 CNAME 重定向。
 * 第四部分是主配置结构体 config，聚合所有子配置并提供统一的构造接口。
 *
 * 地址解析规则：无 scheme 前缀默认为 UDP 协议；tcp:// 前缀使用 TCP；
 * tls:// 前缀使用 TLS (DoT, 端口 853)；https:// 前缀使用 HTTPS (DoH,
 * 端口 443)。支持显式指定端口，未指定时使用协议默认端口。
 */
#pragma once

#include <chrono>
#include <cstddef>

#include <boost/asio.hpp>

#include <prism/memory/container.hpp>

namespace psm::resolve
{
    namespace net = boost::asio;

    // 上游协议类型

    /**
     * @enum dns_protocol
     * @brief DNS 上游服务器协议类型。
     * @details 定义与上游 DNS 服务器通信时使用的传输协议。不同协议提供
     * 不同级别的安全性和性能特征。UDP 最低开销但无加密；TCP 提供可靠传输；
     * TLS 加密全部流量 (DoT)；HTTPS 通过 HTTPS 通道传输 DNS 查询 (DoH)。
     */
    enum class dns_protocol : std::uint8_t
    {
        udp,  // 纯 UDP，如 1.2.3.4 或 udp://1.2.3.4
        tcp,  // TCP，如 tcp://1.2.3.4
        tls,  // TLS (DoT)，如 tls://dns.example.com，默认端口 853
        https // HTTPS (DoH)，如 https://dns.example.com/dns-query，默认端口 443
    };

    // 上游服务器

    /**
     * @struct dns_remote
     * @brief DNS 上游服务器配置。
     * @details 描述一个上游 DNS 服务器的连接参数，包括地址、协议、端口、
     * 超时时间和 TLS 相关选项。支持 UDP、TCP、TLS (DoT) 和 HTTPS (DoH)
     * 四种协议。对于 TLS 和 HTTPS 协议，hostname 字段用于 SNI 和 Host 头。
     * 对于 DoH 协议，http_path 字段指定查询路径，默认为 /dns-query。
     */
    struct dns_remote
    {
        memory::string address;                   // 原始地址字符串
        dns_protocol protocol{dns_protocol::udp}; // 通信协议
        memory::string hostname;                  // TLS SNI / HTTP Host
        std::uint16_t port{53};                   // 服务端口
        std::uint32_t timeout_ms{5000};           // 超时时间（毫秒）
        memory::string http_path;                 // DoH 路径，默认 /dns-query
        bool no_check_certificate{false};         // 跳过 TLS 证书验证

        /**
         * @brief 构造上游服务器配置。
         * @param mr 内存资源，用于内部 PMR 容器分配。
         * @details 若 mr 为 nullptr，则使用 memory::current_resource()。
         */
        explicit dns_remote(memory::resource_pointer mr = memory::current_resource())
            : address(mr), hostname(mr), http_path("/dns-query", mr)
        {
        }
    };

    // 解析模式

    /**
     * @enum resolve_mode
     * @brief DNS 解析查询模式。
     * @details 控制当配置了多个上游服务器时，查询请求的调度策略。
     * fastest 模式并发查询所有上游并选择延迟最低的响应；first 模式并发
     * 查询所有上游并返回首个成功响应；fallback 模式按顺序逐一尝试上游，
     * 前一个失败后才尝试下一个。
     */
    enum class resolve_mode : std::uint8_t
    {
        fastest, // 并发查询所有上游，选择 RTT 最低的成功响应
        first,   // 并发查询所有上游，返回第一个成功响应
        fallback // 按顺序尝试上游，前一个失败后尝试下一个
    };

    // 域名规则

    /**
     * @struct address_rule
     * @brief DNS 地址映射规则。
     * @details 将特定域名映射到预定义的 IP 地址列表。支持通配符匹配，
     * 例如 "*.example.com" 可匹配任意子域名。negative 标志指示该域名
     * 应返回 NXDOMAIN（否定应答），适用于广告拦截等场景。
     */
    struct address_rule
    {
        memory::string domain;                      // 匹配域名，支持通配符 *.xxx.com
        memory::vector<net::ip::address> addresses; // 映射的地址列表
        bool negative{false};                       // 否定应答（NXDOMAIN）

        /**
         * @brief 构造地址映射规则。
         * @param mr 内存资源，用于内部 PMR 容器分配。
         * @details 若 mr 为 nullptr，则使用 memory::current_resource()。
         */
        explicit address_rule(memory::resource_pointer mr = memory::current_resource())
            : domain(mr), addresses(mr)
        {
        }
    };

    /**
     * @struct cname_rule
     * @brief DNS CNAME 重定向规则。
     * @details 将特定域名的 A/AAAA 查询重定向到另一个域名（CNAME 记录）。
     * 适用于域名别名和负载均衡等场景。
     */
    struct cname_rule
    {
        memory::string domain; // 源域名
        memory::string target; // CNAME 目标域名

        /**
         * @brief 构造 CNAME 重定向规则。
         * @param mr 内存资源，用于内部 PMR 容器分配。
         * @details 若 mr 为 nullptr，则使用 memory::current_resource()。
         */
        explicit cname_rule(memory::resource_pointer mr = memory::current_resource())
            : domain(mr), target(mr)
        {
        }
    };

    // 主配置

    /**
     * @struct config
     * @brief DNS 解析器主配置。
     * @details 聚合 DNS 解析器的所有配置项，包括上游服务器列表、解析策略、
     * 缓存参数、TTL 钳制范围、域名规则和 IP 黑名单。
     *
     * 上游服务器列表 (servers) 定义可用的 DNS 上游服务器，解析策略 (mode)
     * 决定查询调度方式。缓存配置控制 DNS 响应的本地缓存行为，包括容量、
     * TTL 和过期数据的提供策略。TTL 钳制 (ttl_min/ttl_max) 限制响应中
     * TTL 值的范围，防止过短或过长的 TTL。域名规则支持地址映射和
     * CNAME 重定向。IP 过滤通过黑名单阻止特定网段的解析结果。
     */
    struct config
    {
        memory::vector<dns_remote> servers;       // 上游服务器列表
        resolve_mode mode{resolve_mode::fastest}; // 解析查询模式
        std::uint32_t timeout_ms{5000};           // 全局超时（毫秒）

        // 缓存配置
        bool cache_enabled{true};               // 是否启用 DNS 缓存
        std::size_t cache_size{10000};          // 缓存最大条目数
        std::chrono::seconds cache_ttl{120};    // 缓存默认 TTL
        bool serve_stale{true};                 // 过期后是否仍提供缓存数据
        std::chrono::seconds negative_ttl{300}; // 负缓存 TTL（失败域名缓存时间）

        // TTL 钳制
        std::uint32_t ttl_min{60};    // 最小 TTL（秒）
        std::uint32_t ttl_max{86400}; // 最大 TTL（秒）

        // 域名规则
        memory::vector<address_rule> address_rules; // 地址映射规则列表
        memory::vector<cname_rule> cname_rules;     // CNAME 重定向规则列表

        // 是否禁用 IPv6，启用后跳过 AAAA 查询并过滤 IPv6 端点
        bool disable_ipv6{false};

        // IP 过滤
        memory::vector<net::ip::network_v4> blacklist_v4; // IPv4 黑名单
        memory::vector<net::ip::network_v6> blacklist_v6; // IPv6 黑名单

        /**
         * @brief 构造 DNS 解析器主配置。
         * @param mr 内存资源，用于内部 PMR 容器分配。
         * @details 若 mr 为 nullptr，则使用 memory::current_resource()。
         * 初始化所有 PMR 容器成员。
         */
        config(memory::resource_pointer mr = memory::current_resource())
            : servers(mr),
              address_rules(mr), cname_rules(mr),
              blacklist_v4(mr), blacklist_v6(mr)
        {
        }
    };

} // namespace psm::resolve

#include <glaze/glaze.hpp>

template <>
struct glz::meta<psm::resolve::dns_protocol>
{
    static constexpr auto value = glz::enumerate(
        "udp", psm::resolve::dns_protocol::udp,
        "tcp", psm::resolve::dns_protocol::tcp,
        "tls", psm::resolve::dns_protocol::tls,
        "https", psm::resolve::dns_protocol::https);
};

template <>
struct glz::meta<psm::resolve::resolve_mode>
{
    static constexpr auto value = glz::enumerate(
        "fastest", psm::resolve::resolve_mode::fastest,
        "first", psm::resolve::resolve_mode::first,
        "fallback", psm::resolve::resolve_mode::fallback);
};

template <>
struct glz::meta<psm::resolve::dns_remote>
{
    using T = psm::resolve::dns_remote;
    static constexpr auto value = glz::object(
        "address", &T::address,
        "protocol", &T::protocol,
        "hostname", &T::hostname,
        "port", &T::port,
        "timeout_ms", &T::timeout_ms,
        "http_path", &T::http_path,
        "no_check_certificate", &T::no_check_certificate);
};

template <>
struct glz::meta<psm::resolve::address_rule>
{
    using T = psm::resolve::address_rule;
    static constexpr auto value = glz::object(
        "domain", &T::domain,
        "negative", &T::negative);
};

template <>
struct glz::meta<psm::resolve::cname_rule>
{
    using T = psm::resolve::cname_rule;
    static constexpr auto value = glz::object(
        "domain", &T::domain,
        "target", &T::target);
};

template <>
struct glz::meta<psm::resolve::config>
{
    using T = psm::resolve::config;
    static constexpr auto value = glz::object(
        "servers", &T::servers,
        "mode", &T::mode,
        "timeout_ms", &T::timeout_ms,
        "cache_enabled", &T::cache_enabled,
        "cache_size", &T::cache_size,
        "cache_ttl", &T::cache_ttl,
        "serve_stale", &T::serve_stale,
        "negative_ttl", &T::negative_ttl,
        "ttl_min", &T::ttl_min,
        "ttl_max", &T::ttl_max,
        "address_rules", &T::address_rules,
        "cname_rules", &T::cname_rules,
        "disable_ipv6", &T::disable_ipv6);
};
